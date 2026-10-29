"""Pure fakes only; no native/process/tool-version calls."""
from pathlib import Path
import ast
import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

ATTEMPTS=[]
def audit(event,args):
    if event in ('subprocess.Popen','os.fork','os.forkpty','os.posix_spawn','os.exec','os.system'):
        ATTEMPTS.append(event);raise AssertionError('pure five-case preparation forbids children')
sys.addaudithook(audit)
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
h=load('admission_five_subject',HERE/'s5.py')
helper,frozen=h.dependencies()
seam=load('admission_five_seam',HERE/'seam.py');budget=load('admission_five_budget',HERE/'budget.py')
r=load('admission_five_recording',h.FD_RECORDER)
p=load('admission_five_policy',h.SUPERVISED/'resource_policy.py')
original=load('admission_five_original_tests',h.FROZEN/'admission.test.py')
core=load('admission_five_guardian_fakes',ROOT/'tests/consumer-pg-guardian/guardian.test.py')

class Limits:
    RLIMIT_FSIZE=1
    def setrlimit(self,key,value):self.value=value
    def getrlimit(self,key):return self.value
class FileSignals:
    SIGXFSZ=25;SIG_IGN=1
    def getsignal(self,key):return self.SIG_IGN

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original.AdmissionTests.setUpClass()
        cls.synthetic=original.AdmissionTests('test_exact_five_categories_and_before_after_sql')
        cls.base=original.AdmissionTests.base;cls.admitted=original.AdmissionTests.a
        cls.compare=staticmethod(original.AdmissionTests.compare)
        cls.model=original.m
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='admission-five-pure-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.addCleanup(lambda:self.assertEqual(ATTEMPTS,[]))
    def pool(self):return budget.SharedBudget(p.ResourcePolicy,resource_api=Limits(),signal_api=FileSignals())
    def view(self,pool,index):
        work=self.root/('case-'+str(index));work.mkdir(mode=0o700);(work/'logs').mkdir(mode=0o700)
        view=pool.view();view.prepare(work);view.install();return view,work/'logs'
    def test_frozen_code_identity_and_isolated_baseline_only_load(self):
        original_load=frozen.load
        runner=seam.case_runner(frozen,h.FROZEN/'baseline.py')
        self.assertIs(runner.__code__,frozen.run_case.__code__)
        self.assertIsNot(runner.__globals__,frozen.__dict__);self.assertIs(frozen.load,original_load)
        model=runner.__globals__['load']('admission_phase_model',h.FROZEN/'admission.py')
        self.assertEqual(model.CASES,self.model.CASES)
        self.assertEqual(len(model.CASES),5)
    def test_baseline_ast_changes_only_three_start_nodes(self):
        raw=(h.FROZEN/'baseline.py').read_bytes();old=ast.parse(raw);new=seam.baseline_tree(raw)
        fn=next(n for n in old.body if isinstance(n,ast.FunctionDef))
        index=next(i for i,n in enumerate(fn.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='options' for t in n.targets))
        fn.body[index:index+3]=[ast.parse('f.start_foreground_postgres()').body[0]]
        self.assertEqual(ast.dump(old),ast.dump(new))
    def test_global_worst_case_five_retained_pairs_and_cleanup_headroom(self):
        pool=self.pool()
        for index in range(5):
            view,logs=self.view(pool,index)
            foreground=view.reserve('postgres',logs/'pg.out',logs/'pg.err')
            for path in (foreground.stdout,foreground.stderr):
                with path.open('wb') as stream:stream.truncate(p.STREAM_BYTES)
                path.chmod(0o600)
            startup=view.reserve('pg_ctl',logs/'startup.out',logs/'startup.err');view.release(startup)
            ordinary=view.reserve('psql',logs/'sql.out',logs/'sql.err')
            if index==4:
                stop=view.reserve('pg_ctl',logs/'stop.out',logs/'stop.err',cleanup=True)
                status=view.reserve('pg_ctl',logs/'status.out',logs/'status.err',cleanup=True)
                self.assertEqual(pool.metadata()['currentReservedBytes'],512*1024**2)
                view.release(stop);view.release(status)
            view.release(ordinary)
        self.assertEqual(pool.metadata()['currentReservedBytes'],320*1024**2)
        self.assertTrue(h.shared_budget_is_admissible(pool.metadata()))
    def test_missing_startup_retirement_blocks_fifth_ordinary_and_latches_failure(self):
        pool=self.pool()
        for index in range(5):
            view,logs=self.view(pool,index);view.reserve('postgres',logs/'pg.out',logs/'pg.err')
        startup=view.reserve('pg_ctl',logs/'startup.out',logs/'startup.err')
        with self.assertRaises(ValueError):view.reserve('psql',logs/'sql.out',logs/'sql.err')
        self.assertFalse(pool.metadata()['qualificationAllowed'])
        self.assertEqual(pool.metadata()['currentReservedBytes'],384*1024**2)
        view.release(startup)
    def test_real_guardian_startup_status_retired_before_sql_each_case(self):
        gm=core.m;pool=self.pool();store=r.EvidenceStore(self.root/str(uuid.uuid4()))
        toolroot=self.root/'tools';pg=toolroot/'Postgres.app/Contents/Versions/18/bin';pg.mkdir(parents=True)
        tools={}
        for name in ('postgres','pg_ctl','initdb','psql','node'):
            file=pg/name;file.write_bytes(b'inert pure tool');tools[name]=gm.Executable(file,h.sha(file.read_bytes()))
        for index in range(5):
            work=self.root/('owner-'+str(index));work.mkdir(mode=0o700)
            clock=core.Clock();clock.now=h.time.monotonic();backend=core.Fake(clock);view=pool.view()
            owner=gm.Guardian(work,tools,started=clock(),backend=backend,clock=clock,sleep=clock.sleep,signals=core.Signals(),log_policy=view)
            backend.guardian=owner;owner.install()
            wal=work/'data/pg_wal';wal.mkdir(parents=True)
            with (wal/('0'*24)).open('wb') as stream:stream.truncate(16*1024**2)
            scope='case-'+str(index);f=h.fixture_class(helper,self.base,r)(owner,{'toolchainRoot':str(toolroot)},work,
                store.scope(scope),'pure',pg/'node',recording_store=store,recording_scope=scope,raw_log_policy=view)
            try:
                f.start_foreground_postgres()
                self.assertTrue(all(c.retired for c in owner.children if c.name=='pg_ctl'))
                self.assertEqual(pool.metadata()['currentReservedBytes'],(index+1)*64*1024**2)
                self.assertEqual(f.sql('postgres','fake-select','SELECT raw;'),'')
            finally:clean=owner.finish_owner()
            self.assertTrue(h.cleanup_is_admissible(clean))
            shutdown=h.ordinary_receipts(f,'shutdown-clients.json',lambda c:c.name=='pg_ctl' and c.argv[-1] in ('stop','status'))
            self.assertEqual([c['returncode'] for c in shutdown],[0,3])
        hashes=store.seal();reader=r.EvidenceReader(store.root,expected_index_sha256=hashes['storage-index.json'])
        self.assertIs(reader.validate(),True)
        for index in range(5):h.verify_sql_sources(reader,'case-'+str(index))
        self.assertEqual(pool.metadata()['currentReservedBytes'],320*1024**2)
    def test_shared_exhaustion_cleanup_fallback_runs_actual_fake_clients(self):
        gm=core.m;pool=self.pool();view=pool.view();work=self.root/'fallback';work.mkdir(mode=0o700)
        tools={}
        for name in ('postgres','pg_ctl','initdb','psql','node'):
            path=self.root/name;path.write_bytes(b'inert');tools[name]=gm.Executable(path,h.sha(path.read_bytes()))
        clock=core.Clock();backend=core.Fake(clock)
        owner=gm.Guardian(work,tools,started=clock(),backend=backend,clock=clock,sleep=clock.sleep,signals=core.Signals(),log_policy=view)
        backend.guardian=owner;owner.install();owner.start_postgres()
        for i in range(7):
            # Existing client reservations occupy the entire shared pool.
            view.reserve('reserved',work/'logs'/('x'+str(i)),work/'logs'/('y'+str(i)),cleanup=True)
        clean=owner.finish_owner()
        self.assertTrue(clean['completed']);self.assertFalse(clean['qualificationEligible'])
        clients=[c for c in owner.children if c.name=='pg_ctl']
        self.assertEqual([c.exit_code for c in clients],[0,3]);self.assertTrue(all(c.evidence_fallback for c in clients))
    def test_cancelled_foreground_case_still_finishes_owner(self):
        gm=core.m;pool=self.pool();view=pool.view();work=self.root/'cancel';work.mkdir(mode=0o700)
        tools={}
        for name in ('postgres','pg_ctl','initdb','psql','node'):
            path=self.root/name;path.write_bytes(b'inert');tools[name]=gm.Executable(path,h.sha(path.read_bytes()))
        clock=core.Clock();backend=core.Fake(clock);signals=core.Signals()
        owner=gm.Guardian(work,tools,started=clock(),backend=backend,clock=clock,sleep=clock.sleep,signals=signals,log_policy=view)
        backend.guardian=owner;owner.install()
        try:
            owner.start_postgres();signals.deliver(gm.signal.SIGTERM)
            with self.assertRaises(gm.Cancelled):owner.checkpoint()
        finally:clean=owner.finish_owner()
        self.assertTrue(clean['completed']);self.assertFalse(clean['qualificationEligible'])
        self.assertEqual([c.exit_code for c in owner.children if c.name=='pg_ctl'],[0,3])
        fn=next(n for n in ast.parse((HERE/'s5.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='run_cases')
        self.assertTrue(any(isinstance(n,ast.Try) and any(isinstance(x,ast.Assign) and isinstance(x.value,ast.Call)
            and isinstance(x.value.func,ast.Attribute) and x.value.func.attr=='finish_owner' for x in n.finalbody) for n in ast.walk(fn)))
    def valid_resource(self):
        return dict(inheritedHardFileBytes=32*1024**2,rawLogLogicalReservationBytes=512*1024**2,
            cleanupReservedBytes=128*1024**2,perChildPairReservationBytes=64*1024**2,compactEvidenceBytes=256*1024**2,
            prepared=True,installed=True,parentSigxfszIgnored=True,currentReservedBytes=320*1024**2,
            fixtureFileAdmission=dict(initialRegularFiles=1,largestInitialFileBytes=16*1024**2,observedWalSegmentBytes=[16*1024**2],allInitialFilesWithinHardCap=True))
    def completion_tuple(self,omit_first=False,incomplete=False,bad_startup_type=False):
        store=r.EvidenceStore(self.root/str(uuid.uuid4()));results=[];cleanups=[];pool=self.pool()
        toolroot=self.root/('completion-tools-'+str(uuid.uuid4()));pg=toolroot/'Postgres.app/Contents/Versions/18/bin';pg.mkdir(parents=True)
        gm=core.m;tools={}
        for name in ('postgres','pg_ctl','initdb','psql','node'):
            path=pg/name;path.write_bytes(b'inert completion fixture');tools[name]=gm.Executable(path,h.sha(path.read_bytes()))
        for index,case in enumerate(self.model.CASES,1):
            scope=str(index)+'-'+case['id'];store.scope(scope)
            work=self.root/('completion-work-'+str(uuid.uuid4()));work.mkdir(mode=0o700)
            clock=core.Clock();clock.now=h.time.monotonic();backend=core.Fake(clock);view=pool.view()
            owner=gm.Guardian(work,tools,started=clock(),backend=backend,clock=clock,sleep=clock.sleep,signals=core.Signals(),log_policy=view)
            backend.guardian=owner;self.addCleanup(owner.finish_owner)
            f=None
            try:
                owner.install();wal=work/'data/pg_wal';wal.mkdir(parents=True)
                with (wal/('0'*24)).open('wb') as stream:stream.truncate(16*1024**2)
                f=h.journal_fixture_class(helper,self.base,r)(owner,{'toolchainRoot':str(toolroot)},work,
                    store.scope(scope),'pure-completion',pg/'node',recording_store=store,recording_scope=scope,raw_log_policy=view)
                save=f.save
                def startup(name,value):
                    if bad_startup_type and name=='startup-status.json':
                        value=copy.deepcopy(value);value[0]['returncode']=False
                    return save(name,value)
                with patch.object(f,'save',side_effect=startup):f.start_foreground_postgres()
                self.assertEqual(f.sql(self.base.DATABASES[0],'raw','SELECT raw;\n'),'')
                data=self.synthetic.synthetic(case)
                f.save('actual-fault-catalog.json',data['catalog']);f.save('actual-fault-metadata.json',data['metadata'])
                pristine=[{'section':'schemas','rows':[{'catalog':{'oid':'2200','nspname':'public'}}]}]
                f.save('pristine-reference-old-raw.json',pristine)
                rawcat=(store.root/scope/'actual-fault-catalog.json').read_bytes();rawmeta=(store.root/scope/'actual-fault-metadata.json').read_bytes()
                result=self.model.classify(self.base,self.compare,rawcat,rawmeta,self.admitted[3]['old'],case)
                result.update(sqlSetupExit=0,sqlstate=None,rebuildPristineRefsMatched=True,priorGlobalRoleRepair=False,
                    cleanupMethod='destroy marked cluster; fresh initdb for next case, not cross-cluster raw OID equality')
                if case['default']:result['propagationTables']=list(self.model.NEW_TABLES)
                f.save('admission-result.json',result);results.append(result)
            finally:clean=owner.finish_owner()
            self.assertTrue(h.cleanup_is_admissible(clean))
            h.ordinary_receipts(f,'shutdown-clients.json',lambda child:child.name=='pg_ctl' and child.argv[-1] in ('stop','status'))
            f.materialize_commands()
            item=dict(case=case['id'],scope=scope,cleanup=clean,resourcePolicy=view.metadata(),privateWorkRetained=True,
                commandJournal=f.command_journal_metadata())
            if not(omit_first and index==1):f.save('case-cleanup.json',item)
            cleanups.append(item)
        store.save('admission-results.json',results);hashes=store.seal();index_sha=hashes['storage-index.json']
        if incomplete:
            path=store.root/'storage-index.json';value=json.loads(path.read_bytes());value.update(recordingComplete=False,qualificationAllowed=False)
            path.write_text(json.dumps(value,indent=2)+'\n');index_sha=h.sha(path.read_bytes())
        raw_budget=dict(rawLogLogicalReservationBytes=512*1024**2,cleanupReservedBytes=128*1024**2,currentReservedBytes=320*1024**2,highWaterReservedBytes=448*1024**2,caseViews=5,qualificationAllowed=True)
        manifest=dict(runId=store.root.name,status='PROVISIONAL_ADMISSION_SUBSET_PENDING_ROOT_REVIEW',authoritative=False,
            driverInProcess=True,fullS5Qualified=False,qualification={'S5':False},boundedSubsetCompleted=True,admissionFaultsCompleted=True,
            admissionFaultCount=5,stages={'ADMISSION_SUBSET':'SUBSET_PASS','S5':'SUBSET_PASS'},pinsAccepted=False,derivationAttempted=False,
            measuredOperatorsExecuted=False,originalInputsUnchanged=True,recordingComplete=True,evidenceWriteErrors=[],
            storageIndexSha256=index_sha,cleanup=dict(completed=True,clusters=cleanups),rawLogBudget=raw_budget)
        raw=(json.dumps(manifest,indent=2)+'\n').encode()
        (store.root/'transition-manifest.json').write_bytes(raw);(store.root/'transition-manifest.json').chmod(0o600)
        receipt=dict(status='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO',runId=store.root.name,manifestSha256=h.sha(raw),storageIndexSha256=index_sha,
            driverInProcess=True,admissionFaultCount=5,requiresOwnedControllerExitCode=0,originalOuterDeadlineSeconds=900,
            manifestAloneIsAdmission=False,receiptAloneIsAdmission=False)
        path=store.root/'completion-receipt.json';path.write_bytes(helper.receipt_bytes(receipt));path.chmod(0o600)
        outer=dict(runId=store.root.name,manifestSha256=h.sha(raw),storageIndexSha256=index_sha,driverInProcess=True,
            ownedControllerExitCode=0,originalOuterDeadlineSeconds=900,completed=True,elapsedSeconds=899.9)
        reader=r.EvidenceReader(store.root,expected_index_sha256=index_sha)
        return raw,receipt,outer,reader
    def test_five_phase_results_and_all_five_stored_cleanups_pass(self):
        args=self.completion_tuple();self.assertTrue(h.completion_is_admissible(*args))
    def test_first_cleanup_omission_is_never_hidden_by_diagnostic_tail(self):
        args=self.completion_tuple(omit_first=True)
        with self.assertRaises(r.EvidenceError):h.completion_is_admissible(*args)
    def test_real_false_reader_rejects_even_matching_hashes(self):
        args=self.completion_tuple(incomplete=True);self.assertIs(args[-1].validate(),False)
        self.assertFalse(h.completion_is_admissible(*args))
    def test_closed_actual_outer_binding_and_original_deadline(self):
        raw,receipt,outer,reader=self.completion_tuple()
        for key,value in [('runId',None),('manifestSha256','0'*64),('storageIndexSha256','0'*64),('elapsedSeconds',900),('ownedControllerExitCode',False),('driverInProcess',False)]:
            self.assertFalse(h.completion_is_admissible(raw,receipt,dict(outer,**{key:value}),reader))
        self.assertFalse(h.completion_is_admissible(raw,dict(receipt,extendedCount=18),outer,reader))
        path=reader.root/'completion-receipt.json';path.unlink()
        self.assertFalse(h.completion_is_admissible(raw,receipt,outer,reader))
    def test_false_qualification_and_client_exit_are_exact_types(self):
        raw,receipt,outer,reader=self.completion_tuple()
        manifest=json.loads(raw);manifest['qualification']={'S5':0}
        raw=(json.dumps(manifest,indent=2)+'\n').encode()
        (reader.root/'transition-manifest.json').write_bytes(raw)
        receipt['manifestSha256']=h.sha(raw);outer['manifestSha256']=h.sha(raw)
        (reader.root/'completion-receipt.json').write_bytes(helper.receipt_bytes(receipt))
        self.assertIs(reader.validate(),True)
        self.assertFalse(h.completion_is_admissible(raw,receipt,outer,reader))
        args=self.completion_tuple(bad_startup_type=True)
        self.assertIs(args[-1].validate(),True)
        self.assertFalse(h.completion_is_admissible(*args))
    def test_historical_dependency_code_and_original_globals_unchanged(self):
        original_checked=helper.checked;original_globals=helper.dependencies.__globals__
        function=h.historical_dependency_function(helper)
        self.assertIs(function.__code__,helper.dependencies.__code__)
        self.assertIsNot(function.__globals__,original_globals)
        self.assertIs(original_globals['checked'],original_checked)
        self.assertIs(helper.checked,original_checked)
        self.assertIsNot(function.__globals__['checked'],original_checked)
        function()
        self.assertIs(helper.dependencies.__globals__['checked'],original_checked)
    def test_historical_wrong_tuple_and_changed_archive_reject(self):
        checker=h.historical_dependency_function(helper).__globals__['checked']
        live=ROOT/'tests/consumer-fixture-evidence/recording.py'
        with self.assertRaises(ValueError):checker(live,'0'*64)
        with self.assertRaises((OSError,ValueError)):checker(live.with_name('recording-other.py'),h.OLD_RECORDER_SHA)
        changed=self.root/'changed.py';changed.write_bytes(b'changed historical source');changed.chmod(0o444)
        with patch.object(h,'HISTORICAL_RECORDER',changed):
            with self.assertRaises(ValueError):checker(live,h.OLD_RECORDER_SHA)
        changed.chmod(0o600);changed.write_bytes(h.HISTORICAL_RECORDER.read_bytes());changed.chmod(0o644)
        with patch.object(h,'HISTORICAL_RECORDER',changed):
            with self.assertRaises(ValueError):checker(live,h.OLD_RECORDER_SHA)
        changed.chmod(0o444);os.link(changed,self.root/'extra-link.py')
        with patch.object(h,'HISTORICAL_RECORDER',changed):
            with self.assertRaises(ValueError):checker(live,h.OLD_RECORDER_SHA)
    def test_new_live_recorder_pin_is_separate_and_exact(self):
        live=ROOT/'tests/consumer-fixture-evidence/recording.py'
        self.assertEqual(h.sha(live.read_bytes()),h.NEW_RECORDER_SHA)
        with self.assertRaises(ValueError):h.checked(live,h.OLD_RECORDER_SHA)
        old=self.root/'old.py';old.write_bytes(h.HISTORICAL_RECORDER.read_bytes())
        with self.assertRaises(ValueError):h.checked(old,h.NEW_RECORDER_SHA)
        with patch.object(h,'NEW_RECORDER_SHA','0'*64):
            with self.assertRaisesRegex(ValueError,'approved live recorder pin'):h.dependencies()
    def test_all_other_historical_dependency_checks_delegate(self):
        calls=[]
        def record(path,pin):calls.append((path,pin));return helper.checked(path,pin)
        isolated=SimpleNamespace(dependencies=helper.dependencies,checked=record)
        function=h.historical_dependency_function(isolated);function()
        lock=json.loads((h.SUPERVISED/'inputs.lock.json').read_bytes())
        self.assertEqual(len(calls),2+len(lock['localSha256'])+len(lock['dependenciesSha256']))
        self.assertEqual(sum(path==h.HISTORICAL_RECORDER for path,pin in calls),1)
        for name,pin in lock['dependenciesSha256'].items():
            expected=h.HISTORICAL_RECORDER if name=='tests/consumer-fixture-evidence/recording.py' else ROOT/name
            self.assertIn((expected,pin),calls)
    def test_fd_candidate_wrong_literal_and_changed_source_reject(self):
        self.assertEqual(h.sha(h.FD_RECORDER.read_bytes()),h.FD_RECORDER_SHA)
        with patch.object(h,'FD_RECORDER_SHA','0'*64):
            with self.assertRaisesRegex(ValueError,'approved opt-in FD recorder pin'):h.dependencies()
        bad=self.root/'changed-recorder.py';bad.write_bytes(b'changed staged recorder')
        with patch.object(h,'FD_RECORDER',bad):
            with self.assertRaisesRegex(ValueError,'source substitution'):h.dependencies()
        bad.write_bytes((ROOT/'tests/consumer-fixture-evidence/recording.py').read_bytes())
        with patch.object(h,'FD_RECORDER',bad):
            with self.assertRaisesRegex(ValueError,'source substitution'):h.dependencies()
    def test_fd_optin_keeps_live320_and_historical143_separate(self):
        live=ROOT/'tests/consumer-fixture-evidence/recording.py'
        self.assertNotEqual(h.FD_RECORDER,live)
        self.assertEqual(Path(r.__file__),h.FD_RECORDER)
        self.assertEqual(h.sha(live.read_bytes()),h.NEW_RECORDER_SHA)
        self.assertEqual(h.NEW_RECORDER_SHA,'320f62eca99763416ab4b9058cf29baec69042bfe77794eebd9364484c169c4f')
        self.assertEqual(h.sha(h.HISTORICAL_RECORDER.read_bytes()),h.OLD_RECORDER_SHA)
        lock=json.loads((HERE/'inputs.lock.json').read_bytes())
        self.assertEqual(lock['dependenciesSha256'][h.FD_RECORDER_REL],h.FD_RECORDER_SHA)
        self.assertEqual(lock['dependenciesSha256']['tests/consumer-fixture-evidence/recording.py'],h.NEW_RECORDER_SHA)
    def test_source_pins_and_no_unsafe_main_or_constructor_invocation(self):
        h.dependencies()
        text=(HERE/'s5.py').read_text();tree=ast.parse(text)
        self.assertFalse(any(isinstance(n,ast.Attribute) and n.attr in ('Popen','construct','run_owned') for n in ast.walk(tree)))
        with self.assertRaises(ValueError):h.checked(h.FROZEN/'s5.py','0'*64)

if __name__=='__main__':unittest.main()
