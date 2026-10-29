"""Prepared additional120 owner-denial S5 subset. Runtime requires independent review + root appointment.

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
SOURCE_NAMES=('cases.py','inputs.lock.json','s5.py','owner-faults.test.py','README.md','next-plan.json')
PRIOR=ROOT/'tests/consumer-derivatives-v2-sealing'
DEPENDENCY_LOCK_SHA='0c8b2222c9b9acb99739d0fcd5444091f57fa0ce868c67026a22e09c3f40bac2'


def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def dependencies():
    raw=(HERE/'inputs.lock.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=DEPENDENCY_LOCK_SHA:raise ValueError('dependency lock substitution')
    lock=json.loads(raw)
    for name,pin in lock['dependenciesSha256'].items():
        path=ROOT/name
        if any(p.is_symlink() for p in (path,*path.parents)) or hashlib.sha256(path.read_bytes()).hexdigest()!=pin:
            raise ValueError('prior accepted dependency substitution: '+name)
    root=json.loads((ROOT/lock['priorRootReceipt']).read_bytes())
    if root['status']!='BOUNDED_S5_SUBSET_RESULT_ACCEPTED_FULL_S5_FALSE' or root['fullS5Qualified'] is not False:
        raise ValueError('wrong prior accepted scope')
    return lock


def load_constructor():
    dependencies()
    path=PRIOR/'construct.py'
    if hashlib.sha256(path.read_bytes()).hexdigest()!=CONSTRUCTOR_SHA:raise ValueError('prior constructor substitution')
    return load_module('owner_faults_constructor',path)


def closure(constructor):
    dependencies()
    return {n:constructor.sha((HERE/n).read_bytes()) for n in SOURCE_NAMES}


def run_s5(base,f,inputs,constructor,admitted,derived,manifest):
    lock=dependencies();prior=load_module('owner_faults_prior',PRIOR/'s5.py')
    # Preserve the admitted prior lifecycle/runtime/denial machinery unchanged.
    prior.run_s5(base,f,inputs,constructor,admitted,derived,manifest)
    manifest.update(status='INCOMPLETE',stages={**manifest['stages'],'S5':'INCOMPLETE'},
                    boundedSubsetCompleted=False,ownerFaultsCompleted=False)
    path=HERE/'cases.py'
    if constructor.sha(path.read_bytes())!=lock['caseSourceSha256']:raise ValueError('owner cases substitution')
    builder=load_module('owner_faults_cases',path)
    cases=builder.build(admitted[3]['new']['catalog'],prior.denied_sql)
    f.save('owner-fault-source-cases.json',cases)
    expected=admitted[3]['new'];catalog_sql=inputs['preparationFiles']['catalog-discovery.sql'].decode()
    metadata_sql=base.checked(base.HERE/'pg-s0-s4-metadata.sql').decode();results=[]
    for index,case in enumerate(cases):
        label='owner-fault-'+str(index+1)
        output=f.sql(base.DATABASES[0],label+':'+case['id'],case['sql'])
        base.require(output.strip()=='DENIED_42501','owner-fault permission result missing')
        catalog=f.capture(base.DATABASES[0],label+'-catalog',catalog_sql)
        metadata=f.capture(base.DATABASES[0],label+'-metadata',metadata_sql)
        prior.compare_capture(base,catalog,metadata,expected)
        results.append({'id':case['id'],'status':'PASS','requiredSqlstate':'42501',
            'statementSha256':case['statementSha256'],'fullCatalogAndMetadataUnchanged':True})
        f.save('owner-fault-results.json',results)
    manifest.update(status='PROVISIONAL_S5_SUBSET_PENDING_ROOT_REVIEW',
        stages={**manifest['stages'],'S5':'SUBSET_PASS'},boundedSubsetCompleted=True,fullS5Qualified=False,
        ownerFaultsCompleted=True,ownerFaultCount=len(results),ownerFaultGroup='additional120 owner denials only',
        priorAcceptedSubsetChecks=82,executedSubset='prior82 checks repeated plus120 added42501 owner denials with full catalog/metadata invariance',
        deferredCases='next-plan.json; predecessor/operator-drift/positive-business/S6 all NOT_RUN')
    return manifest


def completion_is_admissible(manifest_bytes,receipt,controller):
    manifest=json.loads(manifest_bytes);elapsed=controller.get('elapsedSeconds')
    return (manifest.get('status')=='PROVISIONAL_S5_SUBSET_PENDING_ROOT_REVIEW'
        and manifest.get('authoritative') is False and manifest.get('cleanup',{}).get('completed') is True
        and manifest.get('originalInputsUnchanged') is True and not manifest.get('evidenceWriteErrors')
        and manifest.get('stages')=={**{s:'PASS' for s in ('S0','S1','S2','S3','S4')},'S5':'SUBSET_PASS'}
        and manifest.get('fullS5Qualified') is False and manifest.get('boundedSubsetCompleted') is True
        and manifest.get('qualification',{}).get('S5') is False
        and manifest.get('ownerFaultsCompleted') is True
        and type(manifest.get('ownerFaultCount')) is int and manifest['ownerFaultCount']==120
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
    evidence=ROOT/'artifacts/consumer-derivatives-v2-s5-owner-faults-runtime'/str(uuid.uuid4());evidence.mkdir(parents=True,exist_ok=False)
    work=Path(tempfile.mkdtemp(prefix='lcd-s5-',dir='/private/tmp'))
    for name in ('home','tmp','socket'):(work/name).mkdir(mode=0o700)
    f=base.Fixture(owned,lock,work,evidence,args.appointment,node);f.started=started
    manifest={'status':'FAILED','authoritative':False,'stages':{'S5':'INCOMPLETE'},'lastStage':None,
        'fullS5Qualified':False,'boundedSubsetCompleted':False,'ownerFaultsCompleted':False,
        'originalPinsModified':False,'pinsFilled':False,'measuredOperatorsExecuted':False,'prismaLedgerQualified':False,
        'laterStages':{s:'NOT_RUN' for s in ('S5','S6','S7','S8')},
        'qualification':{k:False for k in ('S5','HTTP','BetterAuth','UI','Prisma012','production')}}
    error=None;completion=None;tools_after=None
    try:
        f.save('derived-manifest.json',delta)
        for name,raw in derived.items():(evidence/name).write_bytes(raw)
        manifest=run_s5(base,f,inputs,constructor,admitted,derived,manifest)
    except BaseException as exc:
        error=exc;manifest.update(fullS5Qualified=False,boundedSubsetCompleted=False,ownerFaultsCompleted=False,qualification={**manifest['qualification'],'S5':False});manifest['error']=type(exc).__name__+': '+str(exc).replace(str(work),'<owned>')
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
                manifest.update(fullS5Qualified=False,boundedSubsetCompleted=False,ownerFaultsCompleted=False)
                manifest['stages']={**{s:('PASS' if manifest.get('stages',{}).get(s)=='PASS' or (evidence/('stage-'+s+'.json')).exists() else 'NOT_COMPLETED') for s in ('S0','S1','S2','S3','S4')},'S5':'INCOMPLETE'}
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
            error=error or exc;manifest.update(fullS5Qualified=False,boundedSubsetCompleted=False,ownerFaultsCompleted=False);manifest.setdefault('stages',{})['S5']='INCOMPLETE';manifest['status']='UNKNOWN_DEADLINE' if isinstance(exc,base.AppointmentDeadline) else 'FAILED'
            manifest['finalizationError']=type(exc).__name__+': '+str(exc).replace(str(work),'<owned>')
            try:base.remaining_budget(started);f.try_save('transition-manifest.json',manifest)
            except BaseException:pass
        finally:signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps({'status':manifest['status'],'manifest':str(evidence/'transition-manifest.json'),
        'cleanup':manifest.get('cleanup',{}).get('completed',False),'completionReceiptPublished':completion is not None,
        'requiresExternalOwnedControllerExitZero':True}))
    if error:raise SystemExit(1)

if __name__=='__main__':sys.dont_write_bytecode=True;main()
