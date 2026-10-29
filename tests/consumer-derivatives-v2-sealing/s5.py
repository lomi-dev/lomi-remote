"""Prepared S5 subset. Runtime requires independent review + root appointment.

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
import types
import uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
CONSTRUCTOR_SHA='b9ec75b1b593ce9ef94c72706e66ca10a847efac49a79c749424496eee19cf7c'
SOURCE_NAMES=('construct.py','inputs.lock.json','s5.py','sealing.test.py','README.md','fault-cases.json')


def load_constructor():
    path=HERE/'construct.py'
    source=path.read_bytes()
    if hashlib.sha256(source).hexdigest()!=CONSTRUCTOR_SHA:raise ValueError('constructor source substitution')
    constructor=types.ModuleType('fixture_pin_constructor')
    constructor.__file__=str(path)
    constructor.__package__=''
    exec(compile(source,str(path),'exec'),constructor.__dict__)
    return constructor


def closure(constructor):
    return {n:constructor.sha((HERE/n).read_bytes()) for n in SOURCE_NAMES}


def compare_capture(base,catalog,metadata,expected):
    """Closed schema comparison; functions and ACL values are never normalized."""
    base.require(base.canonical(metadata)==base.canonical(expected['metadata']),'metadata differs from admitted independent reference')
    base.require(base.canonical(catalog,base.protected_relation_map(metadata))==
                 base.canonical(expected['catalog'],base.protected_relation_map(expected['metadata'])),
                 'catalog differs from admitted independent reference')


def denied_sql(role,statement):
    roles={'lomi_migrator','lomi_runtime','lomi_remote_api','lomi_remote_exchange'}
    if role not in roles:raise ValueError('unknown denial role')
    literal="'"+statement.replace("'","''")+"'"
    return ('SET SESSION AUTHORIZATION '+role+';\nDO $fixture_denial$ BEGIN\n'
        ' BEGIN EXECUTE '+literal+"; RAISE EXCEPTION 'expected42501 but statement succeeded';\n"
        " EXCEPTION WHEN SQLSTATE '42501' THEN NULL; END;\nEND $fixture_denial$;\n"
        "RESET SESSION AUTHORIZATION;\nSELECT 'DENIED_42501';\n")


def denial_cases(new_catalog):
    signatures = [r['signature'] for r in new_catalog if r.get('kind')=='function' and
        r['signature'].split('(')[0] in ('public.lomi_consumer_inventory',
          'public.lomi_consumer_assertion_recheck','public.lomi_consumer_recipient_recheck',
          'public.lomi_consumer_principal_live_v2','public.lomi_consumer_scalar_recheck_v2')]
    if len(set(signatures))!=5:raise ValueError('denial function allowlist')
    functions={r['signature']:r for r in new_catalog if r.get('kind')=='function'}
    cases=[]
    for role in ('lomi_migrator','lomi_runtime','lomi_remote_api','lomi_remote_exchange'):
        for sig in sorted(signatures):
            definition=bytes.fromhex(functions[sig]['definitionUtf8Hex']).decode('utf8')
            for action,sql in [('replace',definition),('alter','ALTER FUNCTION '+sig+' COST 777;'),('drop','DROP FUNCTION '+sig+';')]:
                cases.append((role+':'+action+':'+sig,denied_sql(role,sql)))
        for owner in ('lomi_consumer_auth_body_owner','lomi_remote_inventory_owner','lomi_remote_pairing_write_owner'):
            cases.append((role+':set-role:'+owner,denied_sql(role,'SET ROLE '+owner)))
        cases.append((role+':grant-membership',denied_sql(role,'GRANT lomi_consumer_auth_body_owner TO '+role)))
    return cases


def run_s5(base,f,inputs,constructor,admitted,derived,manifest):
    # Reconstruct frozen target+two independent references using ONLY reviewed
    # source-selected transcripts. This does not invoke a measured operator yet.
    manifest.update(base.execute(f,inputs))
    manifest.update(fullS5Qualified=False,boundedSubsetCompleted=False,
                    qualification={**manifest['qualification'],'S5':False})
    refs=admitted[3];catalog_sql=inputs['preparationFiles']['catalog-discovery.sql'].decode()
    metadata_sql=base.checked(base.HERE/'pg-s0-s4-metadata.sql').decode()
    def capture(label,expected):
        catalog=f.capture(base.DATABASES[0],label+'-catalog',catalog_sql)
        metadata=f.capture(base.DATABASES[0],label+'-metadata',metadata_sql)
        compare_capture(base,catalog,metadata,expected)
        return catalog,metadata
    for database,state in zip(base.DATABASES,('old','old','new')):
        catalog=json.loads((f.evidence/(database+'-catalog.json')).read_bytes())
        metadata=json.loads((f.evidence/(database+'-metadata.json')).read_bytes())
        compare_capture(base,catalog,metadata,refs[state])
    f.save('S5-prestate-admission.json',{'status':'PASS','allThreeMatchAdmittedIndependentReferences':True})
    events=[]
    def step(name,sql,expected):
        f.sql(base.DATABASES[0],name,sql);capture(name,expected)
        events.append({'case':name,'status':'PASS'});f.save('S5-cases.json',events)
    hybrid={'catalog':json.loads(json.dumps(refs['old']['catalog'])),'metadata':refs['new']['metadata']}
    helpers={r['signature'] for r in admitted[5]['helpers']}
    newfunctions={r['signature']:r for r in refs['new']['catalog'] if r.get('kind')=='function'}
    hybrid['catalog']=[newfunctions[r['signature']] if r.get('kind')=='function' and r['signature'] in helpers else r for r in hybrid['catalog']]
    manifest.update(pinsFilled=True,originalPinsModified=False,measuredOperatorsExecuted=True)
    step('S5-helper-seal',derived['operator-seal-auth-helpers.candidate.sql'].decode(),hybrid)
    step('S5-helper-idempotency',derived['operator-seal-auth-helpers.candidate.sql'].decode(),hybrid)
    step('S5-three-root-transition',derived['operator-three-roots.candidate.sql'].decode(),refs['new'])
    step('S5-three-root-idempotency',derived['operator-three-roots.candidate.sql'].decode(),refs['new'])
    for round_ in (1,2):
        for name in ('ops/database-permissions.sql','ops/remote-database-permissions.sql','ops/push-database-permissions.sql'):
            f.sql(base.DATABASES[0],'S5-ops-'+str(round_)+':'+name,inputs['baselineFiles'][name].decode())
        f.sql(base.DATABASES[0],'S5-fixture-ops-'+str(round_),inputs['preparationFiles']['fixture-ops.sql'].decode())
        capture('S5-ops-final-'+str(round_),refs['new'])
        events.append({'case':'ops-round-'+str(round_),'status':'PASS'});f.save('S5-cases.json',events)
    for label,sql in denial_cases(refs['new']['catalog']):
        result=f.sql(base.DATABASES[0],'S5-denial:'+label,sql)
        base.require(result.strip()=='DENIED_42501','denial result missing')
        capture('S5-denial-'+str(len(events)),refs['new'])
        events.append({'case':label,'status':'PASS','requiredSqlstate':'42501','catalogUnchanged':True})
        f.save('S5-cases.json',events)
    base.require(f.sql(base.DATABASES[0],'S5-ledger-remains-empty','SELECT count(*) FROM public._prisma_migrations;').strip()=='0','ledger gained rows')
    manifest.update(status='PROVISIONAL_S5_SUBSET_PENDING_ROOT_REVIEW',lastStage='S5',
        stages={**manifest['stages'],'S5':'SUBSET_PASS'},fullS5Qualified=False,boundedSubsetCompleted=True,
        laterStages={s:'NOT_RUN' for s in ('S6','S7','S8')},
        pinsFilled=True,originalPinsModified=False,measuredOperatorsExecuted=True,
        derivedCopyScope='separate disposable fixture copies only',
        executedSubset='helper/root transitions and idempotency; ops twice;76 owner denials42501 with exact catalog/metadata invariance',
        deferredCases='fault-cases.json; all PLANNED_NOT_RUN',
        scopeDeviation='Only prepared bounded S5 subset; broad negative matrix remains NOT_RUN; no later qualification')
    return manifest


def completion_is_admissible(manifest_bytes,receipt,controller):
    manifest=json.loads(manifest_bytes);elapsed=controller.get('elapsedSeconds')
    return (manifest.get('status')=='PROVISIONAL_S5_SUBSET_PENDING_ROOT_REVIEW'
        and manifest.get('authoritative') is False and manifest.get('cleanup',{}).get('completed') is True
        and manifest.get('originalInputsUnchanged') is True and not manifest.get('evidenceWriteErrors')
        and manifest.get('stages')=={**{s:'PASS' for s in ('S0','S1','S2','S3','S4')},'S5':'SUBSET_PASS'}
        and manifest.get('fullS5Qualified') is False and manifest.get('boundedSubsetCompleted') is True
        and manifest.get('qualification',{}).get('S5') is False
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
    evidence=ROOT/'artifacts/consumer-derivatives-v2-sealing-runtime'/str(uuid.uuid4());evidence.mkdir(parents=True,exist_ok=False)
    work=Path(tempfile.mkdtemp(prefix='lcd-s5-',dir='/private/tmp'))
    for name in ('home','tmp','socket'):(work/name).mkdir(mode=0o700)
    f=base.Fixture(owned,lock,work,evidence,args.appointment,node);f.started=started
    manifest={'status':'FAILED','authoritative':False,'stages':{'S5':'INCOMPLETE'},'lastStage':None,
        'fullS5Qualified':False,'boundedSubsetCompleted':False,
        'originalPinsModified':False,'pinsFilled':False,'measuredOperatorsExecuted':False,'prismaLedgerQualified':False,
        'laterStages':{s:'NOT_RUN' for s in ('S5','S6','S7','S8')},
        'qualification':{k:False for k in ('S5','HTTP','BetterAuth','UI','Prisma012','production')}}
    error=None;completion=None;tools_after=None
    try:
        f.save('derived-manifest.json',delta)
        for name,raw in derived.items():(evidence/name).write_bytes(raw)
        manifest=run_s5(base,f,inputs,constructor,admitted,derived,manifest)
    except BaseException as exc:
        error=exc;manifest.update(fullS5Qualified=False,boundedSubsetCompleted=False,qualification={**manifest['qualification'],'S5':False});manifest['error']=type(exc).__name__+': '+str(exc).replace(str(work),'<owned>')
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
                manifest.update(fullS5Qualified=False,boundedSubsetCompleted=False)
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
            error=error or exc;manifest.update(fullS5Qualified=False,boundedSubsetCompleted=False);manifest.setdefault('stages',{})['S5']='INCOMPLETE';manifest['status']='UNKNOWN_DEADLINE' if isinstance(exc,base.AppointmentDeadline) else 'FAILED'
            manifest['finalizationError']=type(exc).__name__+': '+str(exc).replace(str(work),'<owned>')
            try:base.remaining_budget(started);f.try_save('transition-manifest.json',manifest)
            except BaseException:pass
        finally:signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps({'status':manifest['status'],'manifest':str(evidence/'transition-manifest.json'),
        'cleanup':manifest.get('cleanup',{}).get('completed',False),'completionReceiptPublished':completion is not None,
        'requiresExternalOwnedControllerExitZero':True}))
    if error:raise SystemExit(1)

if __name__=='__main__':sys.dont_write_bytecode=True;main()
