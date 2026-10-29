"""Pure fake orchestration; denies native/process/dlopen/signaling operations."""
from pathlib import Path
import ast
import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
DENIED=[]
def audit(event,args):
    if event in ('subprocess.Popen','os.fork','os.posix_spawn','os.system','os.kill','os.killpg','ctypes.dlopen'):
        DENIED.append(event);raise AssertionError('native/process operation forbidden')
sys.addaudithook(audit)
lock=json.loads((HERE/'inputs.lock.json').read_bytes())
for path,pin in [(HERE/n,p) for n,p in lock['localSha256'].items()]+[(ROOT/n,p) for n,p in lock['dependenciesSha256'].items()]:
    if hashlib.sha256(path.read_bytes()).hexdigest()!=pin:raise AssertionError('admission before import')
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
h=load('ctas4_supervised',HERE/'s5.py');prepared=load('ctas4_prepared',HERE/'prepared.py')
prior,helper,protocol,modules=h.dependencies();m=modules['model'];cases=m.build()
model_lock=json.loads((h.MODEL/'inputs.lock.json').read_bytes())
baseline=json.loads((ROOT/model_lock['referenceRawCapture']).read_bytes());builtin_rows=json.loads((ROOT/model_lock['referenceBuiltinCapture']).read_bytes());builtins=modules['extended'].admit_builtins(builtin_rows,baseline)
ids=dict(zip(m.OID_KEYS,map(str,(710000013,710000007,710000019,710000001,710000023,710000003,710000031,710000011,710000029,710000017)),strict=True))
class Owner:
    def __init__(self,fail=False):self.calls=[];self.fail=fail
    def install(self):
        self.calls.append('install')
        if self.fail:raise ValueError('install')
    def finish_owner(self):self.calls.append('finish_owner');return {'completed':True}

class FakeFixture:
    def __init__(self):
        self.work=Path(tempfile.mkdtemp(prefix='ctas4-pure-',dir=os.environ['TMPDIR']));self.pg=self.work/'pinned-pg';self.data={};self.capture_labels=[];self.events=[];self.sequence=0;self.recording_store=self
    def save(self,name,value):self.data[name]=copy.deepcopy(value)
    def save_bytes(self,name,value):self.data[name]=value
    def capture(self,db,label,sql):
        self.capture_labels.append((db,label));rows=builtin_rows if label.startswith('ctas-builtin-identities-') else baseline;self.save(label+'.json',rows);return copy.deepcopy(rows)
    def command(self,label,argv,expected):
        self.sequence+=1;case=cases[self.sequence-1];setup=m.expected_setup(case,baseline,ids,builtins);marks=protocol.markers(case)
        metadata=[dict(kind='objectAcl',grantor='e2_owner',grantee='e2_owner'),dict(kind='columnAcl',grantor='e2_owner',grantee='PUBLIC'),dict(kind='schemaAuthority',role='lomi_runtime',create=False),dict(kind='constraint'),dict(kind='trigger'),dict(kind='index'),dict(kind='role',name='e2_owner',**modules['base'].expected_role('e2_owner')),dict(kind='membership',role='pg_a',member='pg_b'),dict(kind='defaultAcl',owner='lomi_migrator',grantor='lomi_migrator',grantee='lomi_runtime'),dict(kind='relationIdentity')]
        stderr='ERROR: 55000: '+protocol.MESSAGE+'\n';self.events.append(dict(stderr=stderr,returncode=3))
        return '\n'.join([marks[0],*[json.dumps(r) for r in setup],marks[1],marks[2],*[json.dumps(r) for r in metadata],marks[3],marks[4],''])+'\n'
    def close(self):
        for f in self.work.iterdir():f.unlink()
        self.work.rmdir()

class Supervised(unittest.TestCase):
    def test_01_dependency_closure_oldarchive_live320(self):
        prior.dependencies();self.assertEqual(prior.NEW_RECORDER_SHA,'320f62eca99763416ab4b9058cf29baec69042bfe77794eebd9364484c169c4f');self.assertEqual(prior.OLD_RECORDER_SHA,'14312e038a7e1333d6efad810711b585678b9166c86015d7bf56194e7ea57933')
    def test_02_compilation_all_four_and_shuffled_ids(self):
        for case in cases:
            compiled=prepared.Prepared(m,case,baseline,builtins);self.assertTrue(compiled.evidence()['compiledBeforeFault']);self.assertEqual(len(compiled.trigger_paths),4)
            self.assertTrue(m.raw_equal(compiled.instantiate(ids),m.expected_setup(case,baseline,ids,builtins)))
            reversedids=dict(zip(m.OID_KEYS,reversed(list(ids.values())),strict=True));self.assertTrue(m.raw_equal(compiled.instantiate(reversedids),m.expected_setup(case,baseline,reversedids,builtins)))
    def test_03_expansion_cannot_derive_fault_fields(self):
        compiled=prepared.Prepared(m,cases[0],baseline,builtins);observed=m.expected_setup(cases[0],baseline,ids,builtins);m.one(m.sections(observed)['objects'],lambda r:r['name']==m.TARGET)['relrowsecurity']=True
        bound=m.bind_identities(cases[0],baseline,observed,builtins);self.assertFalse(m.raw_equal(observed,compiled.instantiate(bound)))
    def test_04_constructor_failure_retains_outer_owner(self):
        g=Owner();f,error,clean=h.owned_phase(g,lambda:(_ for _ in ()).throw(ValueError('constructor')),lambda f:None);self.assertIsNone(f);self.assertIsInstance(error,ValueError);self.assertEqual(g.calls,['install','finish_owner'])
    def test_05_install_failure_reaches_finish(self):
        g=Owner(True);f,error,clean=h.owned_phase(g,lambda:None,lambda f:None);self.assertIsInstance(error,ValueError);self.assertEqual(g.calls,['install','finish_owner'])
    def test_06_parser_record_model_failures_reach_finish(self):
        for cls in (ValueError,OSError,KeyboardInterrupt):
            g=Owner();f,error,clean=h.owned_phase(g,lambda:object(),lambda f:(_ for _ in ()).throw(cls('synthetic failure')));self.assertIsInstance(error,cls);self.assertEqual(g.calls[-1],'finish_owner')
    def test_07_finalize_failure_is_after_finish(self):
        g=Owner();f,error,clean=h.owned_phase(g,lambda:None,lambda f:None)
        with self.assertRaises(ValueError):h.finalize(None,g,f,clean,None,None,None,None,None,{},None,None)
        self.assertEqual(g.calls[-1],'finish_owner')
    def test_08_false_reader_literal_boolean_gate(self):
        for value in (False,None,1,{},[]):
            with self.assertRaises(ValueError):h.check_reader(types.SimpleNamespace(validate=lambda:value))
        h.check_reader(types.SimpleNamespace(validate=lambda:True))
    def test_09_four_case_fake_orchestration_first_last_and3db(self):
        f=FakeFixture();prefix_calls=[]
        real_load=h.load
        def inject(name,path):
            if name=='ctas_pristine_prefix':return types.SimpleNamespace(execute=lambda base,f,inputs:prefix_calls.append('pristine-only'))
            return real_load(name,path)
        try:
            with patch.object(h,'load',inject):results=h.run_cases(modules['base'],f,{},protocol,modules,prepared)
            self.assertEqual(prefix_calls,['pristine-only']);self.assertEqual([r['case'] for r in results],[c['id'] for c in cases]);self.assertEqual(results[0]['case'],'extra-clientClass');self.assertEqual(results[-1]['case'],'replace-class-target')
            self.assertEqual([r['database'] for r in results],[protocol.DATABASES[i%3] for i in range(4)])
            self.assertEqual(sum(label.startswith('before-') for _,label in f.capture_labels),12);self.assertEqual(sum(label.startswith('after-') for _,label in f.capture_labels),12)
            for result in results:self.assertTrue(result['authorityGuard']['pythonGuardValidatedAfterOwnedPsqlReturn']);self.assertFalse(result['authorityGuard']['livePreOperatorPythonGateClaimed'])
        finally:f.close()
    def test_10_all_templates_before_first_command(self):
        f=FakeFixture();real_save=f.save
        def checked_command(*args,**kwargs):
            self.assertEqual(sum(name.startswith('compiled-') for name in f.data),4);self.assertIn('ctas-all-models-compiled-before-faults.json',f.data);return FakeFixture.command(f,*args,**kwargs)
        f.command=checked_command
        with patch.object(h,'load',return_value=types.SimpleNamespace(execute=lambda *a:None)):
            try:h.run_cases(modules['base'],f,{},protocol,modules,prepared)
            finally:f.close()
    def test_11_exact_prefix_source_no012_core_bootstrap(self):
        source=(h.SUPERVISED/'prefix.py').read_text();self.assertIn('base.baseline_steps_with_ledger(old,ledger),old[30]',source);self.assertIn('f.start_foreground_postgres()',source);self.assertNotIn("'start']",source)
        tree=ast.parse((HERE/'s5.py').read_text());calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call)];self.assertFalse(any(isinstance(n.func,ast.Attribute) and n.func.attr=='execute' and isinstance(n.func.value,ast.Name) and n.func.value.id=='base' for n in calls))
    def test_12_main_owner_before_finalization(self):
        source=(HERE/'s5.py').read_text();self.assertLess(source.index('f,error,clean=owned_phase'),source.index('receipt=finalize'));self.assertIn('finally:clean=guardian.finish_owner()',source)
    def test_13_model_protocol_eight_sources_unchanged(self):
        frozen=json.loads((ROOT/'artifacts/consumer-derivatives-v2-s5-pre012-ctas-preparation/d1c22e93-13c1-4b7d-ad8e-d5bbe22f8bf4/freeze.json').read_bytes())
        for name,pin in frozen['sourceSha256'].items():self.assertEqual(hashlib.sha256((h.MODEL/name).read_bytes()).hexdigest(),pin)
    def test_14_live_recorder_exact_sql_byte_roundtrip(self):
        recorder=load('ctas_pure_live_recorder',ROOT/'tests/consumer-fixture-evidence/recording.py');parent=Path(tempfile.mkdtemp(prefix='ctas4-store-',dir=os.environ['TMPDIR']));root=parent/str(__import__('uuid').uuid4())
        try:
            store=recorder.EvidenceStore(root);raw=protocol.branch_sql(cases[0],modules).encode();store.save_bytes('script.sql',raw);store.save_bytes('source-sql-1.sql',raw);store.save('sql-1.json',dict(sql=raw.decode(),stdout=''));hashes=store.seal();reader=recorder.EvidenceReader(root,expected_index_sha256=hashes['storage-index.json']);self.assertIs(reader.validate(),True);self.assertEqual(reader.raw('script.sql'),raw);h.verify_sql_sources(reader)
        finally:
            import shutil
            shutil.rmtree(parent)
    def test_15_external_contract_false_reader_rejected(self):
        with patch.object(h,'dependencies',return_value=(prior,helper,protocol,modules)):
            receipt={key:None for key in ('status','runId','manifestSha256','storageIndexSha256','driverInProcess','ctasCount','requiresOwnedControllerExitCode','originalOuterDeadlineSeconds','manifestAloneIsAdmission','receiptAloneIsAdmission')}
            outer={key:None for key in ('runId','manifestSha256','storageIndexSha256','driverInProcess','ownedControllerExitCode','originalOuterDeadlineSeconds','completed','elapsedSeconds')}
            self.assertFalse(h.completion_is_admissible(b'{}',receipt,outer,types.SimpleNamespace(validate=lambda:False)))
    def test_16_first_unexpected_setup_stops_and_finishes(self):
        f=FakeFixture();original=f.command;g=Owner()
        f.command=lambda *a,**k:original(*a,**k).replace('"checks": 5','"checks": 99',1)
        with patch.object(h,'load',return_value=types.SimpleNamespace(execute=lambda *a:None)):
            try:
                _,error,clean=h.owned_phase(g,lambda:f,lambda f:h.run_cases(modules['base'],f,{},protocol,modules,prepared))
                self.assertIsInstance(error,ValueError);self.assertEqual(f.sequence,1);self.assertEqual(g.calls[-1],'finish_owner')
            finally:f.close()
    def test_17_external_run_stored_hash_and_tuple_binding(self):
        run_id='6a19de90-cbd8-44ab-8904-6ce855b6a3fe';index='a'*64;toolmap={'tool-'+str(i):'b'*64 for i in range(49)}
        clean=dict(completed=True,qualificationEligible=True,qualificationDeadlineExpired=False,ownershipUnresolved=False,evidenceErrors=[],**{k:True for k in ('foregroundPostgresRegistered','startupConfirmed','postmasterNormalExit','pgCtlStatusAbsent','postmasterPidAbsent','socketDirectoryEmpty','allRetainedChildrenReaped')})
        policy=dict(inheritedHardFileBytes=32*1024**2,rawLogLogicalReservationBytes=512*1024**2,cleanupReservedBytes=128*1024**2,perChildPairReservationBytes=64*1024**2,compactEvidenceBytes=256*1024**2,prepared=True,installed=True,parentSigxfszIgnored=True,currentReservedBytes=64*1024**2,fixtureFileAdmission=dict(allInitialFilesWithinHardCap=True,observedWalSegmentBytes=[16*1024**2],initialRegularFiles=1,largestInitialFileBytes=16*1024**2))
        manifest=dict(runId=run_id,status=h.STATUS,authoritative=False,driverInProcess=True,fullS5Qualified=False,qualification={'S5':False},ctasCompleted=True,boundedSubsetCompleted=True,ctasCount=4,first012Committed=False,stages=h.STAGES,sameDatabaseRawProjectionPairs=12,rawPublicSections=27,globalToastCatalogProof=False,businessAndLifecycle=False,originalInputsUnchanged=True,recordingComplete=True,evidenceWriteErrors=[],cleanup=clean,rawLogResourcePolicy=policy,storageIndexSha256=index,postflight=dict(sourceLockSha256=h.sha((HERE/'inputs.lock.json').read_bytes()),toolchainSha256Before=toolmap,toolchainSha256After=toolmap,pythonSha256=helper.PYTHON_SHA,nodeSha256=modules['base'].NODE_HASH,elapsedSeconds=10))
        raw=json.dumps(manifest).encode();receipt=dict(status='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO',runId=run_id,manifestSha256=h.sha(raw),storageIndexSha256=index,driverInProcess=True,ctasCount=4,requiresOwnedControllerExitCode=0,originalOuterDeadlineSeconds=900,manifestAloneIsAdmission=False,receiptAloneIsAdmission=False)
        outer=dict(runId=run_id,manifestSha256=h.sha(raw),storageIndexSha256=index,driverInProcess=True,ownedControllerExitCode=0,originalOuterDeadlineSeconds=900,completed=True,elapsedSeconds=10)
        fake_helper=types.SimpleNamespace(stored_completion_bytes=lambda reader,name:raw if name=='transition-manifest.json' else helper.receipt_bytes(receipt),receipt_bytes=helper.receipt_bytes,PYTHON_SHA=helper.PYTHON_SHA,resource_metadata_is_admissible=helper.resource_metadata_is_admissible)
        fake_modules={'base':types.SimpleNamespace(NODE_HASH=modules['base'].NODE_HASH,admit_sources=lambda:({},None,toolmap,None))}
        reader=types.SimpleNamespace(root=Path('/synthetic')/run_id,index_pin=index,validate=lambda:True)
        with patch.object(h,'dependencies',return_value=(prior,fake_helper,protocol,fake_modules)),patch.object(h,'verify_stored',return_value=[]):
            self.assertTrue(h.completion_is_admissible(raw,receipt,outer,reader))
            # These numeric aliases are rebound to actual stored manifest bytes,
            # matching receipt/outer hashes; rejection must reach the value gate.
            for value in (0,0.0):
                altered=copy.deepcopy(manifest);altered['qualification']={'S5':value};altered_raw=json.dumps(altered).encode()
                altered_receipt=dict(receipt,manifestSha256=h.sha(altered_raw));altered_outer=dict(outer,manifestSha256=h.sha(altered_raw))
                stored=lambda reader,name:altered_raw if name=='transition-manifest.json' else helper.receipt_bytes(altered_receipt)
                with patch.object(fake_helper,'stored_completion_bytes',stored):
                    self.assertFalse(h.completion_is_admissible(altered_raw,altered_receipt,altered_outer,reader),type(value).__name__)
            for key,value in [('runId','7a19de90-cbd8-44ab-8904-6ce855b6a3fe'),('manifestSha256','c'*64),('storageIndexSha256','d'*64),('ownedControllerExitCode',False),('driverInProcess',False),('elapsedSeconds',900),('completed',False),('extra',0)]:
                self.assertFalse(h.completion_is_admissible(raw,receipt,dict(outer,**{key:value}),reader),key)
            fake_helper.stored_completion_bytes=lambda reader,name:b'{}'
            self.assertFalse(h.completion_is_admissible(raw,receipt,outer,reader))
    def test_18_zero_native_audit(self):self.assertEqual(DENIED,[])


    def real_recorded_fake(self):
        recorder=load('ctas_save_once_actual_recorder',ROOT/'tests/consumer-fixture-evidence/recording.py')
        parent=Path(tempfile.mkdtemp(prefix='ctas-save-once-',dir=os.environ['TMPDIR']));store=recorder.EvidenceStore(parent/str(__import__('uuid').uuid4()));f=FakeFixture();f.recording_store=store;f.result_saves=0
        def save(name,value):
            if name=='ctas-results.json':f.result_saves+=1
            return store.save(name,value)
        f.save=save
        return recorder,parent,store,f
    def test_19_real_recorder_four_results_saved_once(self):
        recorder,parent,store,f=self.real_recorded_fake();g=Owner()
        with patch.object(h,'load',return_value=types.SimpleNamespace(execute=lambda *a:None)):
            try:
                _,error,clean=h.owned_phase(g,lambda:f,lambda f:h.run_cases(modules['base'],f,{},protocol,modules,prepared))
                self.assertIsNone(error);self.assertEqual(g.calls[-1],'finish_owner');self.assertEqual(f.sequence,4);self.assertEqual(f.result_saves,1)
                hashes=store.seal();reader=recorder.EvidenceReader(store.root,expected_index_sha256=hashes['storage-index.json']);self.assertIs(reader.validate(),True)
                results=reader.read('ctas-results.json');self.assertEqual([r['case'] for r in results],[c['id'] for c in cases]);self.assertEqual(len(results),4)
                for case in cases:self.assertTrue((store.root/('attempt-'+case['id']+'.json')).is_file())
            finally:
                f.close();__import__('shutil').rmtree(parent)
    def test_20_partial_failure_preserves_cases_and_finishes_owner(self):
        recorder,parent,store,f=self.real_recorded_fake();original=f.command;g=Owner()
        def fail_third(*args,**kwargs):
            if f.sequence==2:raise OSError('synthetic next-owned-command failure')
            return original(*args,**kwargs)
        f.command=fail_third
        with patch.object(h,'load',return_value=types.SimpleNamespace(execute=lambda *a:None)):
            try:
                _,error,clean=h.owned_phase(g,lambda:f,lambda f:h.run_cases(modules['base'],f,{},protocol,modules,prepared))
                self.assertIsInstance(error,OSError);self.assertEqual(g.calls[-1],'finish_owner');self.assertEqual(f.sequence,2);self.assertEqual(f.result_saves,0);self.assertFalse((store.root/'ctas-results.json').exists())
                hashes=store.seal();reader=recorder.EvidenceReader(store.root,expected_index_sha256=hashes['storage-index.json']);self.assertIs(reader.validate(),True)
                for case in cases[:2]:
                    for prefix in ('attempt','setup','expected-setup','actual-metadata','authority-validation'):self.assertIsInstance(reader.read(prefix+'-'+case['id']+'.json'),(dict,list))
                self.assertNotIn('completion-receipt.json',reader.index['files'])
            finally:
                f.close();__import__('shutil').rmtree(parent)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Supervised));print(json.dumps(dict(testsRun=result.testsRun,successful=result.wasSuccessful(),nativeAuditEvents=DENIED,actualNativePGNodeExecuted=False,actualCTASCasesExecuted=0,fullS5Qualified=False)));raise SystemExit(0 if result.wasSuccessful() and not DENIED else 1)
