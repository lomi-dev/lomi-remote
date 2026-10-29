"""Prepared five admission-negative cases, sequential fresh private clusters.

Imports start no children. CLI requires separate root runtime/resource admission.
No fault snapshot is submitted to a pin constructor or sealing operator.
"""
from pathlib import Path
from types import SimpleNamespace
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
LOCK_SHA='de9b33760ed785042e1c80bac57c585bb805a09852df8b1543f07a99e4eab14b'
NAMES=('admission.py','baseline.py','raw-capture.sql','s5.py','inputs.lock.json','admission.test.py','README.md','excluded.json')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def sha(data):return hashlib.sha256(data).hexdigest()


def dependencies():
    raw=(HERE/'inputs.lock.json').read_bytes()
    if sha(raw)!=LOCK_SHA:raise ValueError('admission dependency lock substitution')
    lock=json.loads(raw)
    for name,pin in lock['dependenciesSha256'].items():
        p=ROOT/name
        if any(x.is_symlink() for x in (p,*p.parents)) or sha(p.read_bytes())!=pin:raise ValueError('dependency substitution: '+name)
    for name,pin in lock['localSha256'].items():
        p=HERE/name
        if p.is_symlink() or sha(p.read_bytes())!=pin:raise ValueError('local source substitution: '+name)
    for path_key,pin_key,status in (
        ('acceptedPre012RootReceipt','acceptedPre012RootReceiptSha256','BOUNDED_10_PRE012_SUBSET_ACCEPTED_FULL_S5_FALSE'),
        ('acceptedOperatorRootReceipt','acceptedOperatorRootReceiptSha256','BOUNDED_S5_OPERATOR_FAULT_SUBSET_ACCEPTED_FULL_S5_FALSE')):
        raw=(ROOT/lock[path_key]).read_bytes();accepted=json.loads(raw)
        if sha(raw)!=lock[pin_key] or accepted['status']!=status or accepted['fullS5Qualified'] is not False:raise ValueError('accepted root receipt scope/identity')
    prior=load('admission_accepted_pre012',ROOT/'tests/consumer-derivatives-v2-s5-pre012/s5.py');prior.dependencies()
    return lock


def authorities():
    lock=dependencies()
    # This source-admission method only READS accepted references and original
    # source/tool closure. construct.construct() is NEVER called in this harness.
    c=load('admission_source_authority',ROOT/'tests/consumer-derivatives-v2-sealing/construct.py')
    admitted=c.load_admitted();base=load('admission_pinned_base',ROOT/admitted[0]['driver'])
    compare=load('admission_pinned_compare',ROOT/'tests/consumer-derivatives-v2-sealing/s5.py').compare_capture
    return lock,c,admitted,base,compare


def closure():
    dependencies();return {name:sha((HERE/name).read_bytes()) for name in NAMES}


def capture(base,f,db,label,sql):
    # Intentionally bypass Fixture.capture's automatic authority rejection so
    # fault data is preserved FIRST and original guard phases can be evidenced.
    rows=base.parse_catalog(f.sql(db,label,sql));f.save(label+'.json',rows);return rows


def raw_capture(base,f,db,label):
    rows=capture(base,f,db,label,base.checked(HERE/'raw-capture.sql').decode())
    sections={r['section']:r['rows'] for r in rows}
    base.require(len(rows)==len(sections)==27,'raw27 closure')
    base.require(sections['ledger']==[{'count':0}] and sections['consumerRows']==[{'count':0}],'nonempty fixture')
    return rows


def creator_step(base,f,db,step):
    name=step['id'];marker=lambda point:"SELECT json_build_object('kind','candidateCreator','step','"+name+"','point','"+point+"','currentUser',current_user,'sessionUser',session_user);\n"
    base.require(step['role']=='e2_owner' and sha(step['sql'].encode())==step['emittedSha256'],'source transcript identity')
    result=f.sql(db,'append-unchanged:'+name,marker('before')+step['sql']+'\n'+marker('after'))
    rows=[json.loads(line) for line in result.splitlines() if line.strip()]
    base.require(rows==[dict(kind='candidateCreator',step=name,point=p,currentUser='e2_owner',sessionUser='e2_owner') for p in ('before','after')],'actual candidate creator mismatch')
    f.save('creator-'+str(f.sequence)+'.json',dict(database=db,sourceSqlSha256=step['emittedSha256'],source=step['source'],markers=rows))


def run_case(base,f,inputs,admitted,compare,case):
    model=load('admission_phase_model',HERE/'admission.py');prefix=load('admission_baseline',HERE/'baseline.py')
    built=prefix.execute(base,f,inputs);old=built['referenceOld']['steps'];new=built['referenceNew']['steps']
    base.require(len(old)==36 and len(new)==37 and len(old[30:])==6,'candidate suffix shape')
    for db in base.DATABASES:
        raw=raw_capture(base,f,db,'rebuilt-baseline-'+db)
        base.require(not any(r['catalog']['rolname']=='fixture_unexpected' for r in next(s['rows'] for s in raw if s['section']=='roles')),'unclean unknown role rebuild')
        metadata=capture(base,f,db,'rebuilt-baseline-metadata-'+db,base.checked(base.HERE/'pg-s0-s4-metadata.sql').decode())
        base.reject_authority_drift(metadata)
        base.require(not any(r.get('kind')=='defaultAcl' and r['owner']=='e2_owner' and r['grantee'] in ('fixture_unexpected','lomi_migrator') for r in metadata),'unclean fault default rebuild')
        base.require(not any(r.get('kind')=='columnAcl' and r['relation']=='consumer_authorization' and r['column']=='originId' and r['grantee'] in ('fixture_unexpected','lomi_remote_api') and r['privilege']=='UPDATE' for r in metadata),'unclean fault column rebuild')
    catalog_sql=inputs['preparationFiles']['catalog-discovery.sql'].decode();metadata_sql=base.checked(base.HERE/'pg-s0-s4-metadata.sql').decode()
    # Independently source-built pristine controls BEFORE any unexpected global
    # role exists. Their expected bytes never come from the fault branch.
    for db in base.DATABASES[1:]:
        for step in old[30:]:creator_step(base,f,db,step)
    group=new[-1];base.require(group['kind']=='transaction-group' and sha(group['sql'].encode())==group['emittedSha256'],'new-reference group')
    f.sql(base.DATABASES[2],'independent-new-literal-reference',group['sql'])
    pristine_raw={}
    for db,state in zip(base.DATABASES[1:],('old','new')):
        cat=capture(base,f,db,'pristine-reference-'+state+'-catalog',catalog_sql)
        meta=capture(base,f,db,'pristine-reference-'+state+'-metadata',metadata_sql)
        base.reject_authority_drift(cat);base.reject_authority_drift(meta)
        compare(base,cat,meta,admitted[3][state]);pristine_raw[state]=raw_capture(base,f,db,'pristine-reference-'+state+'-raw')
    target=base.DATABASES[0]
    before=model.setup_before(case)
    if before:f.sql(target,'negative-setup-BEFORE-old30',before)
    raw_capture(base,f,target,'before-candidate-creation-raw')
    for step in old[30:]:creator_step(base,f,target,step)
    after=model.setup_after(case)
    if after:f.sql(target,'negative-setup-AFTER-old35',after)
    # No frozen ops/fixture ops may occur between this point and admission.
    raw=raw_capture(base,f,target,'actual-fault-raw27')
    cat=capture(base,f,target,'actual-fault-catalog',catalog_sql)
    meta=capture(base,f,target,'actual-fault-metadata',metadata_sql)
    namespace=model.pristine_public_namespace_oid(pristine_raw['old'])
    f.save('pristine-public-namespace-identity.json',dict(source='pristine-reference-old-raw.json',sourceSha256=sha((f.evidence/'pristine-reference-old-raw.json').read_bytes()),name='public',oid=namespace))
    qualified_case=dict(case,publicNamespaceOid=namespace)
    model.validate_declared_delta(base,compare,cat,meta,admitted[3]['old'],qualified_case)
    # Exact full capture bytes, not reconstructed fault rows, are admission input.
    result=model.classify(base,compare,(f.evidence/'actual-fault-catalog.json').read_bytes(),(f.evidence/'actual-fault-metadata.json').read_bytes(),admitted[3]['old'],case)
    sections={r['section']:r['rows'] for r in raw}
    if case['default']:
        grantee='fixture_unexpected' if case['unknown'] else 'lomi_migrator'
        tables=[r for r in sections['objects'] if r['name'] in model.NEW_TABLES]
        base.require(len(tables)==3,'new candidate table propagation closure')
        expected_meta=[r for r in meta if r.get('kind')=='objectAcl' and r['relation'] in model.NEW_TABLES and r['grantee']==grantee]
        base.require(len(expected_meta)==3 and all(r['privilege']=='SELECT' and r['grantor']=='e2_owner' and r['owner']=='e2_owner' for r in expected_meta),'default did not propagate to actual new tables')
        result['propagationTables']=list(model.NEW_TABLES)
    result.update(sqlSetupExit=0,sqlstate=None,rebuildPristineRefsMatched=True,priorGlobalRoleRepair=False,cleanupMethod='destroy marked cluster; fresh initdb for next case, not cross-cluster raw OID equality')
    f.save('admission-result.json',result);return result


def completion_is_admissible(raw,receipt,controller):
    m=json.loads(raw);elapsed=controller.get('elapsedSeconds')
    return (m.get('status')=='PROVISIONAL_ADMISSION_SUBSET_PENDING_ROOT_REVIEW' and m.get('authoritative') is False
      and m.get('fullS5Qualified') is False and m.get('boundedSubsetCompleted') is True
      and m.get('admissionFaultsCompleted') is True and type(m.get('admissionFaultCount')) is int and m['admissionFaultCount']==5
      and m.get('stages')=={'ADMISSION_SUBSET':'SUBSET_PASS','S5':'SUBSET_PASS'}
      and m.get('pinsAccepted') is False and m.get('derivationAttempted') is False and m.get('measuredOperatorsExecuted') is False
      and m.get('qualification',{}).get('S5') is False and m.get('cleanup',{}).get('completed') is True
      and m.get('cleanup',{}).get('privateDirectoriesAbsent') is True
      and m.get('originalInputsUnchanged') is True and not m.get('evidenceWriteErrors')
      and receipt.get('status')=='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO' and receipt.get('manifestSha256')==sha(raw)
      and receipt.get('runId')==m.get('runId')==controller.get('runId') and receipt.get('requiresOwnedControllerExitCode')==0
      and receipt.get('originalOuterDeadlineSeconds')==900 and controller.get('originalOuterDeadlineSeconds')==900
      and type(controller.get('ownedControllerExitCode')) is int and controller['ownedControllerExitCode']==0 and controller.get('completed') is True
      and type(elapsed) in (int,float) and 0<=elapsed<900)


def main():
    started=time.monotonic();parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--appointment',required=True);parser.add_argument('--node',required=True,type=Path);args=parser.parse_args()
    def interrupted(sig,frame):raise TimeoutError('original appointment watchdog/interruption '+str(sig))
    signal.signal(signal.SIGALRM,interrupted);signal.setitimer(signal.ITIMER_REAL,840)
    lock,c,admitted,base,compare=authorities();base.require(bool(args.appointment.strip()) and args.node.is_absolute(),'appointment/Node path')
    node=args.node.resolve(strict=True);base.checked(node,base.NODE_HASH);os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    source_before=closure();pglock,inputs,tools_before,support=base.admit_sources();owned=load('admission_owned',support);owned.initialize_process_ownership()
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
    group=ROOT/'artifacts/consumer-derivatives-v2-s5-admission-faults-runtime'/str(uuid.uuid4());group.mkdir(parents=True,exist_ok=False)
    model=load('admission_case_inventory',HERE/'admission.py');results=[];all_clean=[];evidence_errors=[];error=None;active=None;active_cleanup_attempted=False;pending_work=None;private_paths=[];completion=None
    manifest=dict(status='FAILED',runId=group.name,appointment=args.appointment,originalInputsUnchanged=False,evidenceWriteErrors=[],authoritative=False,fullS5Qualified=False,boundedSubsetCompleted=False,admissionFaultsCompleted=False,
        pinsAccepted=False,derivationAttempted=False,pinsFilled=False,measuredOperatorsExecuted=False,prismaLedgerQualified=False,
        qualification={k:False for k in ('S5','S6','S7','S8','HTTP','BetterAuth','UI','Prisma012','production')},laterStages={s:'NOT_RUN' for s in ('S6','S7','S8')})
    try:
        for index,case in enumerate(model.CASES,1):
            base.remaining_budget(started,840);base.require(shutil.disk_usage('/private/tmp').free>=2*1024**3,'need2GiB before each fresh cluster')
            case_evidence=group/(str(index)+'-'+case['id']);case_evidence.mkdir();work=Path(tempfile.mkdtemp(prefix='lcd-admission-',dir='/private/tmp'));pending_work=work;private_paths.append(work)
            for name in ('home','tmp','socket'):(work/name).mkdir(mode=0o700)
            f=base.Fixture(owned,pglock,work,case_evidence,args.appointment,node);f.started=started;active=f;active_cleanup_attempted=False;pending_work=None;case_error=None
            try:result=run_case(base,f,inputs,admitted,compare,case)
            except BaseException as exc:case_error=exc
            finally:
                # Mandatory marked cleanup precedes ALL case-final evidence I/O.
                signal.setitimer(signal.ITIMER_REAL,max(.001,900-(time.monotonic()-started)))
                for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
                active_cleanup_attempted=True
                try:clean=f.cleanup()
                except BaseException as exc:case_error=case_error or exc;clean={'completed':False,'status':'UNKNOWN','error':str(exc)}
                if clean['completed']:active=None
                all_clean.append(dict(case=case['id'],**clean));evidence_errors.extend(f.evidence_errors)
                if not case_error and clean['completed'] and not f.evidence_errors:shutil.rmtree(work)
                f.try_save('case-cleanup.json',dict(cleanup=clean,privateDirectoryAbsent=not work.exists(),error=str(case_error) if case_error else None))
                evidence_errors.extend(x for x in f.evidence_errors if x not in evidence_errors)
            if case_error:raise case_error
            base.require(not evidence_errors and not work.exists(),'case evidence/private cleanup incomplete')
            results.append(result);(group/'admission-results.json').write_text(json.dumps(results,indent=2)+'\n')
            base.remaining_budget(started,840)
            for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
            signal.setitimer(signal.ITIMER_REAL,base.remaining_budget(started,840))
        manifest.update(status='PROVISIONAL_ADMISSION_SUBSET_PENDING_ROOT_REVIEW',stages={'ADMISSION_SUBSET':'SUBSET_PASS','S5':'SUBSET_PASS'},boundedSubsetCompleted=True,admissionFaultsCompleted=True,admissionFaultCount=5)
    except BaseException as exc:error=exc;manifest['error']=type(exc).__name__+': '+str(exc)
    finally:
        signal.setitimer(signal.ITIMER_REAL,max(.001,900-(time.monotonic()-started)))
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
        # If an asynchronous exception escaped per-case setup/finalization,
        # mandatory cleanup remains guarded independently of evidence writes.
        if active is not None and not active_cleanup_attempted:
            try:
                emergency=active;clean=emergency.cleanup();all_clean.append(dict(case='emergency',**clean));evidence_errors.extend(emergency.evidence_errors)
                if clean['completed']:active=None
            except BaseException as exc:error=error or exc;all_clean.append(dict(case='emergency',completed=False,error=str(exc)))
        if pending_work is not None:
            try:shutil.rmtree(pending_work)
            except BaseException as exc:error=error or exc
        manifest['cleanup']={'completed':active is None and all(x['completed'] for x in all_clean),
            'clusters':all_clean,'sequentialClustersOnly':True,'privateDirectoriesAbsent':all(not p.exists() for p in private_paths)}
        manifest.update(caseCountCompleted=len(results),evidenceWriteErrors=evidence_errors)
        try:
            base.remaining_budget(started);tools_after=base.toolchain(pglock);base.require(tools_before==tools_after,'tool drift')
            authorities();base.require(closure()==source_before,'admission source drift');base.checked(node,base.NODE_HASH)
            base.require(len(all_clean)==5 and all(x['completed'] for x in all_clean),'five positive cluster cleanups required')
            if evidence_errors:error=error or OSError('evidence write failures')
            if error:manifest.update(status='FAILED_OR_UNKNOWN',boundedSubsetCompleted=False,admissionFaultsCompleted=False,stages={'ADMISSION_SUBSET':'INCOMPLETE','S5':'INCOMPLETE'})
            manifest.update(runId=group.name,appointment=args.appointment,sourceSha256=source_before,toolchainSha256Before=tools_before,toolchainSha256After=tools_after,
                originalInputsUnchanged=True,elapsedSeconds=round(time.monotonic()-started,6),evidenceWriteErrors=evidence_errors,
                cleanup=manifest['cleanup'],
                rawOidEqualityAcrossClustersClaimed=False,cleanupMethod='positive per-case destroy/rebuild; no revoke-and-bless',caseCountCompleted=len(results))
            manifest['evidenceSha256']={str(p.relative_to(group)):sha(p.read_bytes()) for p in group.rglob('*') if p.is_file() and p.name not in ('transition-manifest.json','completion-receipt.json')}
            base.remaining_budget(started);raw=(json.dumps(manifest,indent=2)+'\n').encode();(group/'transition-manifest.json').write_bytes(raw);base.remaining_budget(started)
            if error is None:completion=base.publish_completion(SimpleNamespace(evidence=group,started=started),sha(raw))
            base.remaining_budget(started)
        except BaseException as exc:
            error=error or exc;manifest.update(status='FAILED_OR_UNKNOWN',boundedSubsetCompleted=False,admissionFaultsCompleted=False,finalizationError=type(exc).__name__+': '+str(exc))
            try:base.remaining_budget(started);(group/'transition-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
            except BaseException:pass
        finally:signal.setitimer(signal.ITIMER_REAL,0)
    print(json.dumps(dict(status=manifest['status'],manifest=str(group/'transition-manifest.json'),cleanup=manifest.get('cleanup'),completionReceiptPublished=completion is not None,requiresExternalOwnedControllerExitZero=True)))
    if error:raise SystemExit(1)

if __name__=='__main__':sys.dont_write_bytecode=True;main()
