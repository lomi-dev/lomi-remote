"""Zero-child tests; pinned interpreter -I -S -B, private HOME/TMP required."""
from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch
from contextlib import redirect_stdout
import io

ATTEMPTS = []
def no_children(event, args):
    if event in ('subprocess.Popen', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec', 'os.system'):
        ATTEMPTS.append(event)
        raise AssertionError('source-only tests prohibit children')
sys.addaudithook(no_children)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec);sys.modules[name] = module
    spec.loader.exec_module(module);return module
h = load('supervised_test_subject', HERE/'s5.py')
r = load('supervised_test_recorder', ROOT/'tests/consumer-fixture-evidence/recording.py')
b = load('supervised_test_base', ROOT/'tests/consumer-derivatives-v2/pg-s0-s4.py')
policy = load('supervised_test_policy',HERE/'resource_policy.py')
model = load('supervised_test_model', HERE/'cases.py')
p = load('supervised_test_protocol', ROOT/'tests/consumer-derivatives-v2-s5-pre012/cases.py')

class FakeGuardian:
    def __init__(self, work, pg):
        self.work = work;self.started = h.time.monotonic();self.calls = []
        self.env = dict(PATH='/usr/bin:/bin', HOME=str(work/'home'), TMPDIR=str(work/'tmp'), LANG='C', LC_ALL='C', TZ='UTC')
        self.tools = {n:SimpleNamespace(path=pg/n) for n in ('postgres','initdb','pg_ctl','psql')}
        self.tools['node'] = SimpleNamespace(path=work/'node')
        self.stdout = '';self.stderr = '';self.returncode = 0
        self.cleaned = self.finished = 0;self.retired = []
    def psql(self, database, path, expected):
        self.calls.append((database, path.read_bytes(), expected))
        return object()
    def tool_version(self, name):self.calls.append(('version', name));return object()
    def result(self, child):
        return SimpleNamespace(returncode=self.returncode,stdout=self.stdout,stderr=self.stderr,evidenceComplete=True,
            stdoutSha256=h.sha(self.stdout.encode()),stderrSha256=h.sha(self.stderr.encode()))
    def retire_result(self,child,**kwargs):self.retired.append((child,kwargs))
    def cleanup(self):self.cleaned += 1;return {'completed':True}
    def finish_owner(self):self.finished += 1;return self.cleanup()
    def observe_qualification(self):return True

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='supervised-pure-');self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(lambda:self.assertEqual(ATTEMPTS, []))
    def fixture(self):
        store = r.EvidenceStore(self.root/str(uuid.uuid4()))
        work = self.root/'work';work.mkdir(mode=0o700)
        for name in ('home','tmp','socket'):(work/name).mkdir(mode=0o700)
        lock = {'toolchainRoot':'fake-pinned-tools'}
        pg = ROOT/lock['toolchainRoot']/'Postgres.app/Contents/Versions/18/bin'
        guardian = FakeGuardian(work, pg)
        f = h.fixture_class(b, r)(guardian, lock, work, store.root, 'pure', work/'node', recording_store=store)
        return f, guardian, store
    def test_exact_frozen_orchestration_ast(self):
        def run(path):return next(n for n in ast.parse(path.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'run_s5')
        old = run(h.FROZEN/'s5.py');new = run(HERE/'s5.py')
        # The entire18 body is identical except the prefix execution source.
        prefix_assignment = next(n for n in old.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'prefix' for t in n.targets))
        prefix_assignment.value.args[1].left = ast.Name(id='HERE', ctx=ast.Load())
        self.assertEqual(ast.dump(old), ast.dump(new))
        for name in ('cases.py','builtin-trigger-identities.sql','excluded.json'):
            self.assertEqual((HERE/name).read_bytes(), (h.FROZEN/name).read_bytes())
    def test_prefix_unchanged_sql_schedule(self):
        old = ast.parse((ROOT/'tests/consumer-derivatives-v2-s5-pre012/prefix.py').read_text())
        new = ast.parse((HERE/'prefix.py').read_text())
        fn = old.body[-1]
        start = next(i for i,n in enumerate(fn.body) if isinstance(n, ast.Assign) and any(isinstance(t,ast.Name) and t.id == 'options' for t in n.targets))
        fn.body[start:start+3] = [ast.parse('f.start_foreground_postgres()').body[0]]
        self.assertEqual(ast.dump(old), ast.dump(new))
    def test_all18_exact_sql_stdout_stderr_and_actual_status(self):
        f, g, store = self.fixture()
        contract = json.loads((ROOT/'staging/consumer-derivatives-v2/predecessor-contract.json').read_bytes())
        cases = model.build(contract)
        operator = (ROOT/'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql').read_text()
        self.assertEqual(len(cases),18);self.assertEqual(cases[-1]['kind'],'reapply')
        for case in cases:
            script = p.branch_sql(case, 'SELECT raw;', operator)
            path = f.work/('extended-'+case['id']+'.sql');path.write_text(script)
            a,z,c,_ = p.markers(case)
            g.stdout = a+'\n[]\n'+z+'\n'+c+'\n\n'
            g.stderr = 'ERROR:  55000: '+p.MESSAGE+'\n';g.returncode = 3
            output = f.command(case['id'], [f.pg/'psql','-X','--no-password','-qAt','-h',f.work/'socket','-p','55439','-U','e2_owner','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-d',b.DATABASES[0],'-f',path], expected=(3,))
            self.assertEqual(output,g.stdout)
            self.assertEqual(f.events[-1]['stderr'],g.stderr)
            self.assertEqual(p.parse_result(case,output,f.events[-1]['stderr'],json.loads),[])
            self.assertEqual(g.calls[-1][1],script.encode())
            self.assertEqual(g.calls[-1][2],(0,3))
        g.returncode = 0;g.stdout = '0\n';g.stderr = ''
        self.assertEqual(f.sql('postgres','zero','SELECT 0;'),'0\n')
        g.stdout = 'x'*70000+'\n\n'
        self.assertEqual(f.sql('postgres','large-text','SELECT raw;'),g.stdout)
        hashes = store.seal();reader = r.EvidenceReader(store.root, expected_index_sha256=hashes['storage-index.json'])
        reader.validate();self.assertEqual(reader.read('commands.json')[-1]['stdout'],g.stdout)
        self.assertEqual(reader.read('sql-'+str(f.sequence)+'.json')['stdout'],g.stdout)
    def test_derived_bytes_and_reader_exactness(self):
        f,g,store = self.fixture();raw = b'-- source\r\nSELECT \'x\';\n\x00'
        store.save_bytes('derived.sql',raw)
        hashes = store.seal();reader = r.EvidenceReader(store.root,expected_index_sha256=hashes['storage-index.json'])
        reader.validate();self.assertEqual(reader.raw('derived.sql'),raw)
        with self.assertRaises(r.EvidenceError):store.save_bytes('late.sql',b'x')
    def exercise_main_failure(self, mode):
        # Inject only the new driver's admission/module/factory seams. Frozen
        # modules, helpers and global process APIs remain untouched.
        node = self.root/'node';node.write_bytes(b'fake-node')
        derived = self.root/'derived';derived.mkdir()
        (derived/'a.sql').write_bytes(b'SELECT 1;')
        (derived/'derived-manifest.json').write_text('{}')
        constructor = SimpleNamespace(load_admitted=lambda:({'driver':'base'},{}),
            construct=lambda:({'a.sql':b'SELECT 1;'},{}))
        lock = dict(toolchainRoot='fake', toolchainCoreSha256={
            'Contents/Versions/18/bin/'+n:'0'*64 for n in ('postgres','initdb','pg_ctl','psql')},
            toolchainInitdbSha256={})
        base = SimpleNamespace(NODE_HASH='0'*64, require=b.require,
            checked=lambda path,*args:Path(path).read_bytes(),
            admit_sources=lambda:(lock,{}, {}, None), toolchain=lambda lock:{})
        owners = []
        class Owner:
            def __init__(self,work,tools,**kwargs):
                self.work=work;self.cleaned=0;self.finished=0;self.evidence_errors=[];self.children=[];owners.append(self)
            def install(self):pass
            def cleanup(self):
                self.cleaned+=1;return dict(completed=True,qualificationEligible=True,qualificationDeadlineExpired=False)
            def finish_owner(self):self.finished+=1;return self.cleanup()
            def observe_qualification(self):return True
        class Fixture:
            def __init__(self,owner,*args,**kwargs):
                self.owner=owner;self.evidence_errors=[];self.store=kwargs['recording_store']
            def save(self,*args):
                if mode == 'recording':self.store.save_bytes('bad.sql','injected non-bytes recorder failure')
                return self.store.save(*args)
            def cleanup(self):return self.owner.cleanup()
        class IncompleteSeal(r.EvidenceStore):
            def seal(self):
                hashes=super().seal()
                path=self.root/'storage-index.json';index=json.loads(path.read_bytes())
                index.update(recordingComplete=False,qualificationAllowed=False)
                raw=(json.dumps(index,indent=2)+'\n').encode();path.write_bytes(raw)
                hashes['storage-index.json']=h.sha(raw);return hashes
        recorder = r if mode == 'recording' else SimpleNamespace(EvidenceStore=IncompleteSeal,EvidenceReader=r.EvidenceReader)
        def fake_run(base,f,inputs,constructor,admitted,derived,manifest):
            f.save('extended-source-cases.json',[{'id':str(i),'kind':'reapply' if i==17 else 'check'} for i in range(18)])
            f.save('extended-results.json',[dict(id=str(i),status='PASS',sqlstate='55000',allThreeDatabasesRawRollback=True) for i in range(18)])
            manifest.update(status='PROVISIONAL_PRE012_EXTENDED_SUBSET_PENDING_ROOT_REVIEW',boundedSubsetCompleted=True,extendedCompleted=True)
        modules = dict(supervised_frozen_constructor=SimpleNamespace(load_constructor=lambda:constructor),
            supervised_pinned_base=base, supervised_compact_recorder=recorder,
            supervised_pg_guardian=SimpleNamespace(Executable=lambda *args:args,Guardian=Owner),
            supervised_resource_policy=SimpleNamespace(ResourcePolicy=lambda:SimpleNamespace(metadata=self.valid_resource_metadata)))
        argv = ['s5.py','--appointment','pure','--node',str(node),'--derived',str(derived)]
        # Keep work creation inside this test's private directory.
        original_mkdtemp = tempfile.mkdtemp
        def private_work(**kwargs):return original_mkdtemp(prefix='owned-',dir=self.root)
        with patch.object(h,'ROOT',self.root), patch.object(h,'dependencies',lambda:{}), \
             patch.object(h,'load_module',lambda name,path:modules[name]), \
             patch.object(h,'fixture_class',lambda *args:Fixture), patch.object(h,'run_s5',fake_run), \
             patch.object(h.tempfile,'mkdtemp',private_work), patch.object(sys,'argv',argv), \
             redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:h.main()
        self.assertEqual(caught.exception.code,1)
        self.assertEqual(len(owners),1);self.assertGreaterEqual(owners[0].cleaned,2)
        self.assertEqual(owners[0].finished,1)
        self.assertEqual(list((self.root/'artifacts').rglob('completion-receipt.json')),[])
        return list((self.root/'artifacts').rglob('transition-manifest.json'))
    def test_main_recorder_failure_still_cleans_and_finishes_owner(self):
        manifests=self.exercise_main_failure('recording')
        self.assertEqual(len(manifests),1)
        self.assertFalse(json.loads(manifests[0].read_bytes())['boundedSubsetCompleted'])
    def test_main_rejects_real_incomplete_reader_without_receipt(self):
        self.exercise_main_failure('incomplete-reader')
        paths=list((self.root/'artifacts').rglob('storage-index.json'))
        self.assertEqual(len(paths),1)
        reader=r.EvidenceReader(paths[0].parent,expected_index_sha256=h.sha(paths[0].read_bytes()))
        self.assertIs(reader.validate(),False)
    def test_adapter_rejects_unknown_argv_before_dispatch(self):
        f,g,store = self.fixture()
        with self.assertRaises(ValueError):f.command('bad',[f.pg/'pg_ctl','start'])
        self.assertEqual(g.calls,[])
    def test_bad_source_pin_rejected_without_launch(self):
        source = self.root/'source.py';source.write_bytes(b'pass\n')
        with self.assertRaises(ValueError):h.checked(source,'0'*64)
        self.assertEqual(ATTEMPTS,[])
        argv = ['s5.py','--appointment','pure','--node',str(source),'--derived',str(self.root)]
        with patch.object(h,'dependencies',side_effect=ValueError('bad source pin')), \
             patch.object(h,'load_module',side_effect=AssertionError('must not import owner')), \
             patch.object(sys,'argv',argv):
            with self.assertRaisesRegex(ValueError,'bad source pin'):h.main()
    def test_closed_dependencies(self):
        h.dependencies()
        self.assertEqual(h.sha((ROOT/'tests/consumer-derivatives-v2/pg-s0-s4.py').read_bytes()),h.BASE_SHA)
    def valid_resource_metadata(self):
        return dict(inheritedHardFileBytes=32*1024**2,rawLogLogicalReservationBytes=512*1024**2,
            cleanupReservedBytes=128*1024**2,perChildPairReservationBytes=64*1024**2,
            compactEvidenceBytes=256*1024**2,prepared=True,installed=True,parentSigxfszIgnored=True,
            currentReservedBytes=64*1024**2,fixtureFileAdmission=dict(initialRegularFiles=1,
                largestInitialFileBytes=16*1024**2,observedWalSegmentBytes=[16*1024**2],allInitialFilesWithinHardCap=True))
    def completion_tuple(self):
        f,g,store = self.fixture()
        cases = [dict(id=str(i),kind='reapply' if i==17 else 'check') for i in range(18)]
        results = [dict(id=c['id'],status='PASS',sqlstate='55000',allThreeDatabasesRawRollback=True) for c in cases]
        store.save('extended-source-cases.json',cases);store.save('extended-results.json',results)
        hashes = store.seal();index_sha = hashes['storage-index.json']
        reader = r.EvidenceReader(store.root,expected_index_sha256=index_sha)
        manifest = dict(status='PROVISIONAL_PRE012_EXTENDED_SUBSET_PENDING_ROOT_REVIEW',
            authoritative=False,driverInProcess=True,fullS5Qualified=False,qualification={'S5':False},
            stages={'PRE012_PREFIX':'PASS','PRE012_EXTENDED_SUBSET':'SUBSET_PASS','S3':'NOT_RUN','S4':'NOT_RUN'},
            boundedSubsetCompleted=True,extendedCompleted=True,extendedCount=18,first012Committed=True,
            originalInputsUnchanged=True,remainingConstructibleCases=4,
            cleanup=dict(completed=True,qualificationEligible=True,qualificationDeadlineExpired=False,evidenceErrors=[],ownershipUnresolved=False),
            recordingComplete=True,evidenceWriteErrors=[],storageIndexSha256=index_sha,runId=store.root.name,
            rawLogResourcePolicy=self.valid_resource_metadata())
        manifest_sha = store.save('transition-manifest.json',manifest)
        raw = (store.root/'transition-manifest.json').read_bytes()
        receipt = h.publish_receipt(store,manifest_sha,index_sha,g)
        controller = dict(runId=store.root.name,manifestSha256=manifest_sha,storageIndexSha256=index_sha,
            originalOuterDeadlineSeconds=900,ownedControllerExitCode=0,
            completed=True,driverInProcess=True,elapsedSeconds=899.999)
        return raw,receipt,controller,reader
    def test_receipt_exact_count_reader_and_original900(self):
        raw,receipt,controller,reader = self.completion_tuple()
        self.assertEqual(reader.index['eventCount'],0)  # Informational only.
        self.assertTrue(h.completion_is_admissible(raw,receipt,controller,reader))
        for field,value in [('elapsedSeconds',900),('elapsedSeconds',float('nan')),
            ('ownedControllerExitCode',3),('ownedControllerExitCode',False),('driverInProcess',False),
            ('manifestSha256','0'*64),('storageIndexSha256','0'*64),('runId',str(uuid.uuid4())),
            ('manifestSha256','G'*64),('completed',1),('originalOuterDeadlineSeconds',900.0)]:
            self.assertFalse(h.completion_is_admissible(raw,receipt,dict(controller,**{field:value}),reader),(field,value))
        for field,value in [('extendedCount',17),('runId',None),('manifestAloneIsAdmission',True)]:
            self.assertFalse(h.completion_is_admissible(raw,dict(receipt,**{field:value}),controller,reader))
        self.assertFalse(h.completion_is_admissible(raw,dict(receipt,extra=True),controller,reader))
        self.assertFalse(h.completion_is_admissible(raw,receipt,dict(controller,extra=True),reader))
        self.assertFalse(h.completion_is_admissible(raw+b' ',receipt,controller,reader))
        index = reader.root/'storage-index.json';index.write_bytes(index.read_bytes()+b' ')
        with self.assertRaises(r.EvidenceError):h.completion_is_admissible(raw,receipt,controller,reader)
    def test_receipt_missing_or_rebound_stored_exclusions(self):
        raw,receipt,controller,reader = self.completion_tuple()
        manifest_path = reader.root/'transition-manifest.json';receipt_path = reader.root/'completion-receipt.json'
        manifest_path.unlink()
        self.assertFalse(h.completion_is_admissible(raw,receipt,controller,reader))
        manifest_path.write_bytes(raw);manifest_path.chmod(0o600)
        saved_receipt = receipt_path.read_bytes();receipt_path.unlink()
        self.assertFalse(h.completion_is_admissible(raw,receipt,controller,reader))
        receipt_path.write_bytes(saved_receipt+b' ');receipt_path.chmod(0o600)
        self.assertFalse(h.completion_is_admissible(raw,receipt,controller,reader))
        receipt_path.write_bytes(saved_receipt)
        changed = dict(receipt,runId=str(uuid.uuid4()))
        receipt_path.write_bytes(h.receipt_bytes(changed))
        self.assertFalse(h.completion_is_admissible(raw,changed,dict(controller,runId=changed['runId']),reader))
    def test_real_correctly_hashed_incomplete_reader_returns_false(self):
        raw,receipt,controller,reader = self.completion_tuple()
        index_path = reader.root/'storage-index.json'
        index = json.loads(index_path.read_bytes())
        index.update(recordingComplete=False,qualificationAllowed=False)
        index_raw = (json.dumps(index,indent=2)+'\n').encode();index_path.write_bytes(index_raw)
        index_sha = h.sha(index_raw)
        incomplete = r.EvidenceReader(reader.root,expected_index_sha256=index_sha)
        self.assertIs(incomplete.validate(),False)
        manifest = json.loads(raw);manifest['storageIndexSha256']=index_sha
        raw = (json.dumps(manifest,indent=2)+'\n').encode()
        (reader.root/'transition-manifest.json').write_bytes(raw)
        receipt.update(manifestSha256=h.sha(raw),storageIndexSha256=index_sha)
        (reader.root/'completion-receipt.json').write_bytes(h.receipt_bytes(receipt))
        controller.update(manifestSha256=h.sha(raw),storageIndexSha256=index_sha)
        self.assertFalse(h.completion_is_admissible(raw,receipt,controller,incomplete))
    def test_exact_unsanitized_text_recorded_before_retirement(self):
        f,g,store = self.fixture()
        g.stdout = str(f.work)+'\n'+str(ROOT)+'\n'+'x'*70000+'\n\n'
        g.stderr = 'actual stderr '+str(f.work)+'\n\n'
        output = f.sql('postgres','raw-text','SELECT raw;')
        self.assertEqual(output,g.stdout);self.assertEqual(len(g.retired),1)
        self.assertEqual(f.events[-1]['stderr'],g.stderr.replace(str(f.work),'<owned>'))
        hashes = store.seal();reader = r.EvidenceReader(store.root,expected_index_sha256=hashes['storage-index.json'])
        self.assertIs(reader.validate(),True)
        recorded = reader.read('owned-result-1.json')
        self.assertEqual([reader.stdout(item['stdout']) for item in recorded],[g.stdout,g.stderr])
        self.assertEqual([item['rawSha256'] for item in recorded],[h.sha(g.stdout.encode()),h.sha(g.stderr.encode())])
        commands = reader.read('commands.json')
        self.assertEqual(commands[0]['stdout'],g.stdout.replace(str(f.work),'<owned>').replace(str(ROOT),'<repo>'))
    def test_output_save_failure_does_not_retire_and_cleanup_still_runs(self):
        f,g,store = self.fixture();g.stdout = 'actual\n'
        original_save = f.save
        def fail_raw(name,value):
            if name.startswith('owned-result-'):store.save_bytes('bad.sql','not bytes')
            return original_save(name,value)
        f.save = fail_raw
        try:
            with self.assertRaises(r.EvidenceError):f.sql('postgres','raw-failure','SELECT raw;')
        finally:f.cleanup()
        self.assertEqual(g.retired,[]);self.assertEqual(g.cleaned,1)
        self.assertTrue(store.incomplete)
    def make_policy(self):
        class Limits:
            RLIMIT_FSIZE = object()
            def __init__(self):self.values = (-1,-1);self.calls = []
            def setrlimit(self,key,value):self.calls.append((key,value));self.values=value
            def getrlimit(self,key):return self.values
        work = self.root/'policy-work';work.mkdir(mode=0o700)
        (work/'logs').mkdir(mode=0o700)
        limits = Limits();budget = policy.ResourcePolicy(resource_api=limits)
        budget.prepare(work);budget.install()
        return budget,limits,work/'logs'
    def test_raw_reserve_exhaustion_keeps_cleanup_capacity(self):
        budget,limits,logs = self.make_policy()
        self.assertEqual(limits.calls,[(limits.RLIMIT_FSIZE,(32*1024**2,32*1024**2))])
        for i in range(6):budget.reserve('psql',logs/(str(i)+'.out'),logs/(str(i)+'.err'))
        with self.assertRaises(policy.ResourceLimit):budget.reserve('psql',logs/'normal.out',logs/'normal.err')
        for i in range(2):budget.reserve('pg_ctl',logs/('cleanup'+str(i)+'.out'),logs/('cleanup'+str(i)+'.err'),cleanup=True)
        with self.assertRaises(policy.ResourceLimit):budget.reserve('pg_ctl',logs/'overflow.out',logs/'overflow.err',cleanup=True)
        self.assertEqual(budget.metadata()['currentReservedBytes'],512*1024**2)
    def test_raw_release_requires_exact_token_and_absent_verified_paths(self):
        budget,limits,logs = self.make_policy()
        token = budget.reserve('psql',logs/'out',logs/'err')
        for path in (token.stdout,token.stderr):path.write_bytes(b'actual');path.chmod(0o600)
        with self.assertRaises(policy.ResourceLimit):budget.release(token)
        clone = policy.Reservation(token.serial,token.stdout,token.stderr,False)
        with self.assertRaises(policy.ResourceLimit):budget.release(clone)
        for path in (token.stdout,token.stderr):path.unlink()
        budget.release(token)
        self.assertEqual(budget.metadata()['currentReservedBytes'],0)
    def test_raw_cap_drift_or_unreserved_output_fails_admission(self):
        budget,limits,logs = self.make_policy()
        limits.values = (-1,-1)
        with self.assertRaises(policy.ResourceLimit):budget.reserve('psql',logs/'out',logs/'err')
        limits.values = (policy.STREAM_BYTES,policy.STREAM_BYTES)
        (logs/'unknown').write_bytes(b'output')
        with self.assertRaises(policy.ResourceLimit):budget.reserve('pg_ctl',logs/'out',logs/'err',cleanup=True)
    def test_initial_file_metadata_admits16m_wal_rejects_oversized_data(self):
        budget,limits,logs=self.make_policy();data=logs.parent/'data';wal=data/'pg_wal'
        wal.mkdir(parents=True,mode=0o700)
        segment=wal/('0'*24)
        with segment.open('wb') as stream:stream.truncate(16*1024**2)
        admitted=budget.admit_fixture_files(data)
        self.assertEqual(admitted['observedWalSegmentBytes'],[16*1024**2])
        with segment.open('wb') as stream:stream.truncate(32*1024**2)
        with self.assertRaises(policy.ResourceLimit):budget.admit_fixture_files(data)
        with segment.open('wb') as stream:stream.truncate(32*1024**2+1)
        with self.assertRaises(policy.ResourceLimit):budget.admit_fixture_files(data)
    def test_file_signal_guard_precedes_cap_and_rechecks_admission(self):
        class Limits:
            RLIMIT_FSIZE=1
            def __init__(self):self.calls=[];self.value=(-1,-1)
            def setrlimit(self,key,value):self.calls.append(value);self.value=value
            def getrlimit(self,key):return self.value
        class Signals:
            SIGXFSZ=1;SIG_IGN=2
            def __init__(self,value):self.value=value
            def getsignal(self,key):return self.value
        work=self.root/'signal-work';work.mkdir(mode=0o700);(work/'logs').mkdir(mode=0o700)
        for handler in (0,lambda *args:None):
            limits=Limits();signals=Signals(handler)
            budget=policy.ResourcePolicy(resource_api=limits,signal_api=signals);budget.prepare(work)
            with self.assertRaises(policy.ResourceLimit):budget.install()
            self.assertEqual(limits.calls,[]);self.assertFalse(budget.installed)
        limits=Limits();signals=Signals(Signals.SIG_IGN)
        budget=policy.ResourcePolicy(resource_api=limits,signal_api=signals);budget.prepare(work);budget.install()
        signals.value=0
        with self.assertRaises(policy.ResourceLimit):budget.reserve('psql',work/'logs/out',work/'logs/err')
        self.assertEqual(len(limits.calls),1)
    def test_resource_metadata_requires_measured_install_and_file_admission(self):
        value=self.valid_resource_metadata();self.assertTrue(h.resource_metadata_is_admissible(value))
        for key,changed in [('installed',False),('parentSigxfszIgnored',False),('fixtureFileAdmission',None),('inheritedHardFileBytes',32.0*1024**2)]:
            self.assertFalse(h.resource_metadata_is_admissible(dict(value,**{key:changed})))
    def test_real_guardian_retirement_preserves_compact_text_and_cleanup(self):
        gm = load('supervised_policy_guardian',ROOT/'tests/consumer-pg-guardian/guardian.py')
        class Limits:
            RLIMIT_FSIZE = 1
            def setrlimit(self,key,value):self.value=value
            def getrlimit(self,key):return self.value
        class Signals:
            ITIMER_REAL = 1
            def getsignal(self,sig):return 0
            def signal(self,sig,handler):pass
            def setitimer(self,*args):pass
        class Backend:
            def initialize(self):self.children=[]
            def spawn(self,argv,**kwargs):
                self.raw_out = (str(work)+'\r\n'+str(ROOT)+'\r'+'x'*70000+'\n\n').encode()
                self.raw_err = ('stderr '+str(work)+'\r\n\r\n').encode()
                kwargs['stdout'].write(self.raw_out);kwargs['stderr'].write(self.raw_err)
                handle=SimpleNamespace(pid=4242,reaped=False);self.children.append(handle);return handle
            def peek(self,handle):return 0
            def other_live_group_members(self,handle):return []
            def reap(self,handle,timeout):handle.reaped=True;return 0
        work = self.root/'real-policy-work';work.mkdir(mode=0o700)
        toolroot = self.root/'tools';pg = toolroot/'Postgres.app/Contents/Versions/18/bin';pg.mkdir(parents=True)
        tools = {}
        for name in ('postgres','pg_ctl','initdb','psql','node'):
            path=pg/name;path.write_bytes(b'inert pinned fake')
            tools[name]=gm.Executable(path,h.sha(path.read_bytes()))
        backend=Backend();budget=policy.ResourcePolicy(resource_api=Limits())
        owner=gm.Guardian(work,tools,started=h.time.monotonic(),backend=backend,signals=Signals(),log_policy=budget)
        store=r.EvidenceStore(self.root/str(uuid.uuid4()))
        owner.install()
        f=h.fixture_class(b,r)(owner,{'toolchainRoot':str(toolroot)},work,store.root,'pure',pg/'node',recording_store=store)
        try:output=f.sql('postgres','real-fake-log','SELECT raw;')
        finally:cleanup=owner.finish_owner()
        self.assertTrue(cleanup['completed'])
        normalized=lambda raw:raw.decode().replace('\r\n','\n').replace('\r','\n')
        self.assertEqual(output,normalized(backend.raw_out))
        self.assertTrue(owner.children[0].retired)
        self.assertEqual(list((work/'logs').iterdir()),[])
        self.assertEqual(budget.metadata()['currentReservedBytes'],0)
        hashes=store.seal();reader=r.EvidenceReader(store.root,expected_index_sha256=hashes['storage-index.json'])
        self.assertIs(reader.validate(),True)
        streams=reader.read('owned-result-1.json')
        self.assertEqual([reader.stdout(item['stdout']) for item in streams],
            [normalized(backend.raw_out),normalized(backend.raw_err)])
        self.assertEqual([item['rawSha256'] for item in streams],[h.sha(backend.raw_out),h.sha(backend.raw_err)])
        self.assertEqual(reader.read('commands.json')[0]['stdout'],
            output.replace(str(work),'<owned>').replace(str(ROOT),'<repo>'))
    def test_main_always_finishes_owner(self):
        main = next(n for n in ast.parse((HERE/'s5.py').read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        owners = [n for n in ast.walk(main) if isinstance(n,ast.Try) and any(isinstance(x,ast.Assign) and isinstance(x.value,ast.Call) and isinstance(x.value.func,ast.Attribute) and x.value.func.attr == 'finish_owner' for x in n.finalbody)]
        self.assertEqual(len(owners),1)

if __name__ == '__main__':unittest.main()
