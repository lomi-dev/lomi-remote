"""Five fresh-cluster admission cases, source-only until separate root admission."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import math
import os
import resource
import stat
from types import FunctionType
import re
import shutil
import sys
import tempfile
import time
import uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
FROZEN=ROOT/'tests/consumer-derivatives-v2-s5-admission-faults'
SUPERVISED=ROOT/'tests/consumer-derivatives-v2-s5-pre012-supervised'
OLD_RECORDER_SHA='14312e038a7e1333d6efad810711b585678b9166c86015d7bf56194e7ea57933'
NEW_RECORDER_SHA='320f62eca99763416ab4b9058cf29baec69042bfe77794eebd9364484c169c4f'
FD_RECORDER_REL='artifacts/consumer-fixture-evidence-composed/2026-10-20-nonblocking-correction/candidate/recording.py'
FD_RECORDER=ROOT/FD_RECORDER_REL
FD_RECORDER_SHA='b95ec6c33bda8a5331224cbd5aa258eaff2684b0d357e585e5f4858ecad8883c'
HISTORICAL_RECORDER=ROOT/'artifacts/consumer-derivatives-v2-s5-admission-supervised-recorder-pin/ae647cd8-38ae-45bb-aea0-e60351d44227/historical/recording.py'
ACCEPTED_18=ROOT/'artifacts/consumer-supervised18-root-result/bf15b98c-1cff-4fc4-8625-a3c2425d47ef'
FROZEN_SHA='3d464d1feece1577a86f443d85cc1643b48933003c7bac762877dc255db8559b'
COMMAND_JOURNAL_REL='artifacts/consumer-fixture-evidence-composed/2026-10-20-nonblocking-correction/candidate/journal.py'
COMMAND_JOURNAL_SHA='d92c36ef8a6ca7093916bfce1b18e8e55241b4d8ba1436aa8289585499e3b916'


def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module

def checked(path,pin):
    if any(p.is_symlink() for p in (path,*path.parents)) or sha(path.read_bytes())!=pin:
        raise ValueError('source substitution: '+str(path))

def historical_dependency_function(helper):
    """Historical14312 closure only; live320f62 is admitted separately below."""
    live=ROOT/'tests/consumer-fixture-evidence/recording.py'
    def historical_checked(path,pin):
        if path==live:
            if pin!=OLD_RECORDER_SHA:raise ValueError('historical recorder tuple mismatch')
            info=HISTORICAL_RECORDER.lstat()
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o444
                or info.st_nlink!=1 or info.st_uid!=os.getuid()):raise ValueError('historical recorder copy identity')
            return helper.checked(HISTORICAL_RECORDER,pin)
        return helper.checked(path,pin)
    original=helper.dependencies
    return FunctionType(original.__code__,dict(original.__globals__,checked=historical_checked),
        original.__name__,original.__defaults__,original.__closure__)


def admit_accepted_eighteen():
    accepted=json.loads((ACCEPTED_18/'receipt.json').read_bytes())
    outer_raw=(ACCEPTED_18/'external-observation.json').read_bytes();outer=json.loads(outer_raw)
    runtime=ROOT/accepted['runtime']
    manifest_raw=(runtime/'transition-manifest.json').read_bytes();manifest=json.loads(manifest_raw)
    receipt_raw=(runtime/'completion-receipt.json').read_bytes();receipt=json.loads(receipt_raw)
    index_sha=sha((runtime/'storage-index.json').read_bytes())
    if not (accepted['status']=='BOUNDED_18_PRE012_EXTENDED_SUBSET_ACCEPTED_FULL_S5_FALSE'
        and accepted['fullS5Qualified'] is False and accepted['extendedCount']==18
        and accepted['sameDatabaseRawProjectionPairs']==54 and accepted['indexedEvidenceHashed']==980
        and accepted['independentResultReviewClosed'] is True and accepted['actualOuterToolExitCode']==0
        and accepted['S3']==accepted['S4']=='NOT_RUN'
        and accepted['externalObservationSha256']==sha(outer_raw)
        and accepted['completionReceiptSha256']==sha(receipt_raw)
        and accepted['manifestSha256']==sha(manifest_raw)==outer['manifestSha256']==receipt['manifestSha256']
        and accepted['storageIndexSha256']==index_sha==outer['storageIndexSha256']==receipt['storageIndexSha256']==manifest['storageIndexSha256']
        and accepted['runId']==outer['runId']==receipt['runId']==manifest['runId']
        and outer['completed'] is True and outer['driverInProcess'] is True
        and type(outer['ownedControllerExitCode']) is int and outer['ownedControllerExitCode']==0
        and outer['originalOuterDeadlineSeconds']==900 and type(outer['elapsedSeconds']) in (int,float)
        and 0<=outer['elapsedSeconds']<900 and math.isfinite(outer['elapsedSeconds'])
        and receipt['status']=='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO' and receipt['driverInProcess'] is True
        and receipt['extendedCount']==18 and manifest['extendedCount']==18
        and manifest['fullS5Qualified'] is False and manifest['boundedSubsetCompleted'] is True
        and manifest['extendedCompleted'] is True and manifest['cleanup']['completed'] is True):
        raise ValueError('accepted historical eighteen proof chain')


def dependencies():
    checked(FROZEN/'s5.py',FROZEN_SHA)
    path=HERE/'inputs.lock.json'
    if path.is_symlink():raise ValueError('source lock symlink')
    lock=json.loads(path.read_bytes())
    if {p.name for p in HERE.iterdir()}!=set(lock['localSha256'])|{'inputs.lock.json'}:
        raise ValueError('new source allowlist')
    for name,pin in lock['localSha256'].items():checked(HERE/name,pin)
    for name,pin in lock['dependenciesSha256'].items():checked(ROOT/name,pin)
    if lock['dependenciesSha256']['tests/consumer-fixture-evidence/recording.py']!=NEW_RECORDER_SHA:
        raise ValueError('approved live recorder pin required')
    if lock['dependenciesSha256'].get(FD_RECORDER_REL)!=FD_RECORDER_SHA:
        raise ValueError('approved opt-in FD recorder pin required')
    checked(FD_RECORDER,FD_RECORDER_SHA)
    checked(ROOT/COMMAND_JOURNAL_REL,COMMAND_JOURNAL_SHA)
    helper=load('admission_supervised_helper',SUPERVISED/'s5.py')
    historical_dependency_function(helper)();admit_accepted_eighteen()
    frozen=load('admission_frozen_driver',FROZEN/'s5.py');frozen.dependencies()
    return helper,frozen


def ordinary_receipts(f,name,predicate):
    records=[];retire=[]
    for child in f.guardian.children:
        if child.retired or not predicate(child):continue
        result=f.guardian.result(child)
        if result.evidenceComplete is not True:raise ValueError('ordinary receipt evidence incomplete')
        records.append(dict(argv=list(result.argv),pid=result.pid,returncode=result.returncode,
            stdout=result.stdout,stderr=result.stderr,stdoutSha256=result.stdoutSha256,stderrSha256=result.stderrSha256))
        retire.append((child,result))
    f.save(name,records)
    for child,result in retire:
        if f.guardian.retire_result(child,stdout_sha256=result.stdoutSha256,stderr_sha256=result.stderrSha256) is not True:
            raise ValueError('ordinary retirement incomplete')
    return records


def fixture_class(helper,base,recorder):
    parent=helper.fixture_class(base,recorder)
    class Fixture(parent):
        def sql(self,database,label,sql):
            self.recording_store.save_bytes('source-sql-'+str(self.sequence+1)+'.sql',sql.encode(),scope=self.recording_scope)
            return super().sql(database,label,sql)
        def start_foreground_postgres(self):
            super().start_foreground_postgres()
            rows=ordinary_receipts(self,'startup-status.json',lambda c:c.name=='pg_ctl' and c.argv[-1]=='status')
            if len(rows)!=1 or rows[0]['returncode']!=0:raise ValueError('one actual startup status0 required')
    return Fixture


def journal_fixture_class(helper,base,recorder):
    journal=load('admission_lossless_command_journal',ROOT/COMMAND_JOURNAL_REL)
    return journal.journal_fixture_class(fixture_class,helper,base,recorder)


def verify_command_journals(reader,scope,metadata,base):
    journal=load('admission_lossless_journal_verifier',ROOT/COMMAND_JOURNAL_REL)
    return journal.verify_command_journals(reader,scope,metadata,repository=ROOT,databases=(*base.DATABASES,'postgres'))


def verify_case(reader,scope,case,model,base,compare,admitted):
    cat_raw=reader.raw(scope+'/actual-fault-catalog.json')
    meta_raw=reader.raw(scope+'/actual-fault-metadata.json')
    pristine=reader.read(scope+'/pristine-reference-old-raw.json')
    namespace=model.pristine_public_namespace_oid(pristine)
    model.validate_declared_delta(base,compare,json.loads(cat_raw),json.loads(meta_raw),
        admitted[3]['old'],dict(case,publicNamespaceOid=namespace))
    expected=model.classify(base,compare,cat_raw,meta_raw,admitted[3]['old'],case)
    result=reader.read(scope+'/admission-result.json')
    extras=dict(sqlSetupExit=0,sqlstate=None,rebuildPristineRefsMatched=True,priorGlobalRoleRepair=False,
        cleanupMethod='destroy marked cluster; fresh initdb for next case, not cross-cluster raw OID equality')
    if case['default']:extras['propagationTables']=list(model.NEW_TABLES)
    if not exact_json(result,{**expected,**extras}):raise ValueError('stored original admission classification mismatch')
    return result


def exact_json(left,right):
    return json.dumps(left,sort_keys=True,allow_nan=False)==json.dumps(right,sort_keys=True,allow_nan=False)


def verify_sql_sources(reader,scope):
    records={name for name in reader.index['files'] if re.fullmatch(re.escape(scope)+r'/sql-[0-9]+\.json',name)}
    sources={name for name in reader.index['files'] if re.fullmatch(re.escape(scope)+r'/source-sql-[0-9]+\.sql',name)}
    if not records or len(records)!=len(sources):raise ValueError('case SQL source closure')
    for name in records:
        sequence=Path(name).stem.removeprefix('sql-')
        if reader.raw(scope+'/source-sql-'+sequence+'.sql')!=reader.read(name)['sql'].encode():
            raise ValueError('case SQL exact bytes mismatch')


def shared_budget_is_admissible(value):
    fixed={'rawLogLogicalReservationBytes':512*1024**2,'cleanupReservedBytes':128*1024**2,
        'currentReservedBytes':320*1024**2,'caseViews':5}
    return (type(value) is dict and set(value)==set(fixed)|{'highWaterReservedBytes','qualificationAllowed'}
        and all(type(value.get(k)) is int and value[k]==v for k,v in fixed.items())
        and type(value['highWaterReservedBytes']) is int and 320*1024**2<=value['highWaterReservedBytes']<=512*1024**2
        and value['qualificationAllowed'] is True)


def cleanup_is_admissible(clean):
    return (type(clean) is dict and clean.get('completed') is True
        and clean.get('qualificationEligible') is True and clean.get('qualificationDeadlineExpired') is False
        and clean.get('ownershipUnresolved') is False and clean.get('evidenceErrors')==[]
        and all(clean.get(k) is True for k in ('foregroundPostgresRegistered','startupConfirmed','postmasterNormalExit',
            'pgCtlStatusAbsent','postmasterPidAbsent','socketDirectoryEmpty','allRetainedChildrenReaped')))


def completion_is_admissible(raw,receipt,outer,reader):
    helper,frozen=dependencies()
    receipt_keys={'status','runId','manifestSha256','storageIndexSha256','driverInProcess','admissionFaultCount',
        'requiresOwnedControllerExitCode','originalOuterDeadlineSeconds','manifestAloneIsAdmission','receiptAloneIsAdmission'}
    outer_keys={'runId','manifestSha256','storageIndexSha256','driverInProcess','ownedControllerExitCode',
        'originalOuterDeadlineSeconds','completed','elapsedSeconds'}
    if type(raw) is not bytes or type(receipt) is not dict or type(outer) is not dict or set(receipt)!=receipt_keys or set(outer)!=outer_keys:return False
    if reader.validate() is not True:return False
    try:
        if helper.stored_completion_bytes(reader,'transition-manifest.json')!=raw:return False
        if helper.stored_completion_bytes(reader,'completion-receipt.json')!=helper.receipt_bytes(receipt):return False
        m=load('admission_completion_recording',ROOT/'tests/consumer-fixture-evidence/recording.py').strict_json(raw);run_id=receipt['runId']
        if type(run_id) is not str or str(uuid.UUID(run_id))!=run_id:return False
    except (OSError,ValueError,TypeError):return False
    if type(m) is not dict:return False
    elapsed=outer['elapsedSeconds']
    hashes=(receipt['manifestSha256'],receipt['storageIndexSha256'],outer['manifestSha256'],outer['storageIndexSha256'])
    if any(type(x) is not str or len(x)!=64 or any(c not in '0123456789abcdef' for c in x) for x in hashes):return False
    if not (run_id==reader.root.name==m.get('runId')==outer['runId']
        and receipt['manifestSha256']==sha(raw)==outer['manifestSha256']
        and receipt['storageIndexSha256']==reader.index_pin==m.get('storageIndexSha256')==outer['storageIndexSha256']
        and receipt['status']=='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO' and receipt['driverInProcess'] is True
        and type(receipt['admissionFaultCount']) is int and receipt['admissionFaultCount']==5
        and receipt['manifestAloneIsAdmission'] is False and receipt['receiptAloneIsAdmission'] is False
        and type(receipt['requiresOwnedControllerExitCode']) is int and receipt['requiresOwnedControllerExitCode']==0
        and type(receipt['originalOuterDeadlineSeconds']) is int and receipt['originalOuterDeadlineSeconds']==900
        and type(outer['originalOuterDeadlineSeconds']) is int and outer['originalOuterDeadlineSeconds']==900
        and type(outer['ownedControllerExitCode']) is int and outer['ownedControllerExitCode']==0
        and outer['completed'] is True and outer['driverInProcess'] is True
        and type(elapsed) in (int,float) and 0<=elapsed<900 and math.isfinite(elapsed)
        and m.get('status')=='PROVISIONAL_ADMISSION_SUBSET_PENDING_ROOT_REVIEW'
        and m.get('authoritative') is False and m.get('driverInProcess') is True
        and m.get('fullS5Qualified') is False and type(m.get('qualification')) is dict
        and set(m['qualification'])=={'S5'} and m['qualification']['S5'] is False
        and m.get('boundedSubsetCompleted') is True and m.get('admissionFaultsCompleted') is True
        and type(m.get('admissionFaultCount')) is int and m['admissionFaultCount']==5
        and m.get('stages')=={'ADMISSION_SUBSET':'SUBSET_PASS','S5':'SUBSET_PASS'}
        and m.get('pinsAccepted') is False and m.get('derivationAttempted') is False
        and m.get('measuredOperatorsExecuted') is False and m.get('originalInputsUnchanged') is True
        and m.get('recordingComplete') is True and m.get('evidenceWriteErrors')==[]
        and type(m.get('cleanup')) is dict and m['cleanup'].get('completed') is True
        and shared_budget_is_admissible(m.get('rawLogBudget'))):return False
    _,_,admitted,base,compare=frozen.authorities()
    model=load('admission_completion_model',FROZEN/'admission.py')
    results=[];cleanups=[]
    for index,case in enumerate(model.CASES,1):
        scope=str(index)+'-'+case['id']
        verify_sql_sources(reader,scope)
        result=verify_case(reader,scope,case,model,base,compare,admitted);results.append(result)
        item=reader.read(scope+'/case-cleanup.json')
        verify_command_journals(reader,scope,item['commandJournal'],base)
        if not (item.get('case')==case['id'] and item.get('scope')==scope and cleanup_is_admissible(item.get('cleanup'))
            and helper.resource_metadata_is_admissible(item.get('resourcePolicy'))):return False
        startup=reader.read(scope+'/startup-status.json');shutdown=reader.read(scope+'/shutdown-clients.json')
        if any(type(r.get('returncode')) is not int for r in startup):return False
        if [r['returncode'] for r in startup]!=[0] or [r['argv'][-1] for r in startup]!=['status']:return False
        if any(type(r.get('returncode')) is not int for r in shutdown):return False
        if [r['returncode'] for r in shutdown]!=[0,3] or [r['argv'][-1] for r in shutdown]!=['stop','status']:return False
        cleanups.append(item)
    return (exact_json(reader.read('admission-results.json'),results) and exact_json(m['cleanup'].get('clusters'),cleanups)
        and len(cleanups)==5 and reader.validate() is True
        and helper.stored_completion_bytes(reader,'transition-manifest.json')==raw
        and helper.stored_completion_bytes(reader,'completion-receipt.json')==helper.receipt_bytes(receipt))


def publish_completion(helper,store,manifest_sha,index_sha,owners):
    if len(owners)!=5 or not all(g.observe_qualification() for g in owners):raise ValueError('original900 qualification closed')
    receipt=dict(status='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO',runId=store.root.name,manifestSha256=manifest_sha,
        storageIndexSha256=index_sha,driverInProcess=True,admissionFaultCount=5,requiresOwnedControllerExitCode=0,
        originalOuterDeadlineSeconds=900,manifestAloneIsAdmission=False,receiptAloneIsAdmission=False)
    pending=store.root/'completion-receipt.pending.json'
    with os.fdopen(os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as stream:stream.write(helper.receipt_bytes(receipt))
    os.replace(pending,store.root/'completion-receipt.json')
    if not all(g.observe_qualification() for g in owners):raise ValueError('original900 qualification closed')
    return receipt


def run_cases(helper,frozen,base,admitted,compare,inputs,pglock,node,store,appointment,started,guardian_module,pool,recorder):
    model=load('admission_case_inventory',FROZEN/'admission.py')
    runner=load('admission_case_seam',HERE/'seam.py').case_runner(frozen,FROZEN/'baseline.py')
    pg=ROOT/pglock['toolchainRoot']/'Postgres.app/Contents/Versions/18/bin'
    pins={**pglock['toolchainCoreSha256'],**pglock['toolchainInitdbSha256']}
    tools={n:guardian_module.Executable(pg/n,pins['Contents/Versions/18/bin/'+n]) for n in ('postgres','initdb','pg_ctl','psql')}
    tools['node']=guardian_module.Executable(node,base.NODE_HASH)
    results=[];cleanups=[];owners=[]
    for index,case in enumerate(model.CASES,1):
        base.remaining_budget(started,840)
        base.require(shutil.disk_usage('/private/tmp').free>=2*1024**3,'need2GiB before each cluster')
        scope=str(index)+'-'+case['id'];evidence=store.scope(scope)
        work=Path(tempfile.mkdtemp(prefix='lcd-admission-supervised-',dir='/private/tmp')).resolve()
        policy=pool.view();g=guardian_module.Guardian(work,tools,started=started,run_id=store.root.name,log_policy=policy)
        owners.append(g);f=None;case_error=None;result=None
        try:
            g.install()
            try:
                f=journal_fixture_class(helper,base,recorder)(g,pglock,work,evidence,appointment,node,
                    recording_store=store,recording_scope=scope,raw_log_policy=policy)
                result=runner(base,f,inputs,admitted,compare,case)
            finally:
                if f is not None:f.cleanup()
        except BaseException as exc:case_error=exc
        finally:clean=g.finish_owner()  # UNKNOWN cannot advance or exit the sole owner.
        item=dict(case=case['id'],scope=scope,cleanup=clean,resourcePolicy=policy.metadata(),privateWorkRetained=True)
        cleanups.append(item)
        if f is not None:
            ordinary_receipts(f,'shutdown-clients.json',lambda c:c.name=='pg_ctl' and c.argv[-1] in ('stop','status'))
            item['resourcePolicy']=policy.metadata()
            f.materialize_commands();item['commandJournal']=f.command_journal_metadata()
            f.save('case-cleanup.json',item)
        if case_error is not None:raise case_error
        base.require(cleanup_is_admissible(clean) and not f.evidence_errors and g.observe_qualification(),'unqualified case cleanup')
        results.append(result);store.save('admission-results.json',results)
    return results,cleanups,owners


def main():
    started=time.monotonic();parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--appointment',required=True);parser.add_argument('--node',required=True,type=Path);args=parser.parse_args()
    helper,frozen=dependencies()
    if Path(sys.executable)!=helper.PYTHON or not(sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):raise ValueError('pinned Python -I-S-B required')
    helper.checked(helper.PYTHON,helper.PYTHON_SHA)
    _,constructor,admitted,base,compare=frozen.authorities()
    base.require(bool(args.appointment.strip()) and args.node.is_absolute(),'appointment/absoluteNode required')
    node=args.node.resolve(strict=True);base.checked(node,base.NODE_HASH)
    pglock,inputs,tools_before,_unused_support=base.admit_sources()
    lock_before=(HERE/'inputs.lock.json').read_bytes()
    recorder=load('admission_recorder',FD_RECORDER)
    guardian=load('admission_guardian',ROOT/'tests/consumer-pg-guardian/guardian.py')
    policy=load('admission_resource_policy',SUPERVISED/'resource_policy.py')
    budgets=load('admission_shared_budget',HERE/'budget.py');pool=budgets.SharedBudget(policy.ResourcePolicy)
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    group=ROOT/'artifacts/consumer-derivatives-v2-s5-admission-supervised-runtime'/str(uuid.uuid4());group.parent.mkdir(parents=True,exist_ok=True)
    store=recorder.EvidenceStore(group);error=None;completion=None
    manifest=dict(status='FAILED',runId=group.name,authoritative=False,driverInProcess=True,fullS5Qualified=False,
        boundedSubsetCompleted=False,admissionFaultsCompleted=False,pinsAccepted=False,derivationAttempted=False,
        measuredOperatorsExecuted=False,pinsFilled=False,qualification={'S5':False},stages={'ADMISSION_SUBSET':'INCOMPLETE','S5':'INCOMPLETE'},
        privateOwnedDirectoriesRetained=True,rawOidEqualityAcrossClustersClaimed=False)
    try:
        results,cleanups,owners=run_cases(helper,frozen,base,admitted,compare,inputs,pglock,node,store,args.appointment,started,guardian,pool,recorder)
        dependencies();constructor.load_admitted();base.checked(node,base.NODE_HASH)
        base.require((HERE/'inputs.lock.json').read_bytes()==lock_before,'new source lock drift')
        tools_after=base.toolchain(pglock);base.require(tools_after==tools_before,'tool drift')
        base.require(len(results)==len(cleanups)==len(owners)==5,'all five clusters required')
        hashes=store.seal();index_sha=hashes['storage-index.json']
        reader=recorder.EvidenceReader(group,expected_index_sha256=index_sha)
        base.require(reader.validate() is True,'reader incomplete')
        model=load('admission_final_model',FROZEN/'admission.py')
        for index,case in enumerate(model.CASES,1):
            scope=str(index)+'-'+case['id'];verify_sql_sources(reader,scope)
            base.require(verify_case(reader,scope,case,model,base,compare,admitted)==results[index-1],'stored case result drift')
            base.require(reader.read(scope+'/case-cleanup.json')==cleanups[index-1],'all five stored cleanups required')
            verify_command_journals(reader,scope,cleanups[index-1]['commandJournal'],base)
            base.require(helper.resource_metadata_is_admissible(cleanups[index-1]['resourcePolicy']),'resource metadata admission')
        base.require(shared_budget_is_admissible(pool.metadata()),'five retained foreground log reservations required')
        manifest.update(status='PROVISIONAL_ADMISSION_SUBSET_PENDING_ROOT_REVIEW',boundedSubsetCompleted=True,
            admissionFaultsCompleted=True,admissionFaultCount=5,stages={'ADMISSION_SUBSET':'SUBSET_PASS','S5':'SUBSET_PASS'},
            originalInputsUnchanged=True,recordingComplete=True,evidenceWriteErrors=[],storageIndexSha256=index_sha,
            cleanup=dict(completed=True,clusters=cleanups,sequentialClustersOnly=True),rawLogBudget=pool.metadata(),
            evidenceSha256=hashes,sourceLockSha256=sha(lock_before),toolchainSha256Before=tools_before,toolchainSha256After=tools_after,
            elapsedSeconds=round(time.monotonic()-started,6))
        manifest_sha=store.save('transition-manifest.json',manifest)
        completion=publish_completion(helper,store,manifest_sha,index_sha,owners)
        base.require(reader.validate() is True,'reader incomplete after receipt')
    except BaseException as exc:
        error=exc;manifest.update(status='FAILED_OR_UNKNOWN',boundedSubsetCompleted=False,admissionFaultsCompleted=False,
            recordingComplete=False,qualificationAllowed=False,error=type(exc).__name__+': '+str(exc),rawLogBudget=pool.metadata())
        try:
            if not store.sealed:store.seal()
            store.save('transition-manifest.json',manifest)
        except BaseException:pass
    print(json.dumps(dict(status=manifest['status'],manifest=str(group/'transition-manifest.json'),driverInProcess=True,
        completionReceiptPublished=completion is not None,requiresExternalOwnedControllerExitZero=True)))
    if error is not None:raise SystemExit(1)

if __name__=='__main__':sys.dont_write_bytecode=True;main()
