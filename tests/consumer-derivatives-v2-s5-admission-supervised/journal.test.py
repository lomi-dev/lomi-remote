"""Pure retained fake Guardian + exact frozen command chain, no Native."""
from pathlib import Path
import copy
import ast
from types import SimpleNamespace
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=Path('/Users/woro/Documents/Lomi/lomi-remote')
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
h=load('journal_current_five',HERE/'s5.py');helper,frozen=h.dependencies()
_,_,_,base,_=frozen.authorities()
r=load('journal_fd_recorder',h.FD_RECORDER)
j=load('journal_candidate',HERE/'journal.py')
core=load('journal_guardian_pure',ROOT/'tests/consumer-pg-guardian/guardian.test.py')

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='journal-pure-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.counter=0
    def fixture(self,threshold=16):
        self.counter+=1;parent=self.root/str(self.counter);parent.mkdir(mode=0o700)
        work=parent/'work';work.mkdir(mode=0o700);pg=parent/'tools/Postgres.app/Contents/Versions/18/bin';pg.mkdir(parents=True)
        tools={}
        for name in ('postgres','pg_ctl','initdb','psql','node'):
            file=pg/name;file.write_bytes(b'inert fake');tools[name]=core.m.Executable(file,h.sha(file.read_bytes()))
        clock=core.Clock();clock.now=time.monotonic();backend=core.Fake(clock)
        owner=core.m.Guardian(work,tools,started=clock(),backend=backend,clock=clock,sleep=clock.sleep,signals=core.Signals());backend.guardian=owner;owner.install()
        self.addCleanup(owner.finish_owner)
        store=r.EvidenceStore(parent/'evidence',threshold=threshold);scope='1-unknown-role'
        cls=h.journal_fixture_class(helper,base,r)
        f=cls(owner,{'toolchainRoot':str(parent/'tools')},work,store.scope(scope),'pure',pg/'node',recording_store=store,recording_scope=scope)
        backend.output=b'';backend.error=b'';backend.code=0
        def output(name,child):
            _,out,err=backend.output_sinks[-1];out.write(backend.output);out.flush();err.write(backend.error);err.flush();child.code=backend.code
        backend.on_spawn=output
        return f,owner,backend,store,scope
    def command(self,f):return f.command('version',[f.pg/'psql','--version'])
    def finish(self,f,g,store,scope):
        g.finish_owner();f.materialize_commands();metadata=f.command_journal_metadata();f.save('case-cleanup.json',{'commandJournal':metadata})
        hashes=store.seal();reader=r.EvidenceReader(store.root,expected_index_sha256=hashes['storage-index.json']);return reader,metadata
    def verify(self,reader,scope,metadata):return j.verify_command_journals(reader,scope,metadata,repository=base.ROOT,databases=(*base.DATABASES,'postgres'))

    def test_exact_frozen_chain_journal_precedes_every_retire_and_one_history_write(self):
        f,g,b,s,scope=self.fixture();codes=[cls.__dict__['command'].__code__ for cls in type(f).__mro__ if 'command' in cls.__dict__]
        self.assertIn(base.Fixture.command.__code__,codes)
        writes=[];original=s.save;retire=g.retire_result;seen=[]
        def saving(name,value,**kwargs):writes.append(name);return original(name,value,**kwargs)
        def retiring(child,**kwargs):
            raw=s._verify(scope+'/owned-result-'+str(f.sequence)+'.json');self.assertEqual(len(r.strict_json(raw)),3)
            self.assertNotIn('commands.json',writes);seen.append(f.sequence);return retire(child,**kwargs)
        with patch.object(s,'save',saving),patch.object(g,'retire_result',retiring):
            for n in range(3):self.assertEqual(self.command(f),'')
            g.finish_owner();f.materialize_commands()
        self.assertEqual(seen,[1,2,3]);self.assertEqual(writes.count('commands.json'),1)
        self.assertEqual(sum(name.startswith('owned-result-') for name in writes),3)
        self.assertEqual(s.max_names,4096);self.assertEqual(s.max_bytes,256*1024**2)
        with self.assertRaises(ValueError):f.materialize_commands()

    def test_large_unicode_crlf_paths_streams_exact_legacy_and_sql_binding(self):
        f,g,b,s,scope=self.fixture();text='α\r\n'+str(f.work)+'\r\n'+str(base.ROOT)+'\n'+'rows\n'*20000
        b.output=text.encode();b.error=('notice '+str(f.work)+'\r\n').encode()
        returned=f.sql(base.DATABASES[0],'actual SQL','SELECT 1;\n')
        self.assertEqual(returned,text.replace('\r\n','\n'))
        reader,meta=self.finish(f,g,s,scope);self.assertTrue(self.verify(reader,scope,meta))
        journal=reader.read(scope+'/owned-result-1.json');self.assertEqual(len(journal),3)
        self.assertEqual(reader.stdout(journal[1]['stdout']),returned)
        self.assertEqual(reader.stdout(journal[0]['stdout']),returned.replace(str(f.work),'<owned>').replace(str(base.ROOT),'<repo>'))
        self.assertEqual(journal[1]['rawSha256'],j.sha(b.output));self.assertNotEqual(journal[1]['rawSha256'],j.sha(returned.encode()))
        history=reader.read(scope+'/commands.json');self.assertEqual(history[0]['stdout'],reader.stdout(journal[0]['stdout']))
        self.assertEqual(reader.raw(scope+'/source-sql-1.sql'),b'SELECT 1;\n')
        self.assertEqual(len(reader.index['files'][scope+'/owned-result-1.json']['stdoutRefs']),3)

    def test_failure_and_swallowed_cleanup_save_never_retire(self):
        for cleanup in (False,True):
            f,g,b,s,scope=self.fixture();save=s.save;retired=[]
            def failing(name,value,**kwargs):
                if name.startswith('owned-result-'):raise OSError('journal write failed')
                return save(name,value,**kwargs)
            with patch.object(s,'save',failing),patch.object(g,'retire_result',side_effect=lambda *a,**kw:retired.append(True)):
                with self.assertRaises((OSError,ValueError)):f.command('version',[f.pg/'psql','--version'],cleanup=cleanup)
            self.assertTrue(f.journal_failed);self.assertEqual(retired,[]);self.assertTrue(g.finish_owner()['completed'])
            self.assertTrue(all(not child.retired for child in g.children))

    def test_conflicting_helper_stream_or_child_and_disk_tamper_block_retirement(self):
        for kind in ('streams','child','disk'):
            f,g,b,s,scope=self.fixture();save=f.save;retired=[]
            def intercepted(name,value):
                if name.startswith('owned-result-'):
                    if kind=='streams':value=copy.deepcopy(value);value[0]['rawSha256']='0'*64
                    elif kind=='child':f.owned.last_child=copy.copy(f.owned.last_child)
                    else:
                        path=s.root/scope/name;path.chmod(0o600);raw=path.read_bytes();path.write_bytes(raw.replace(b'command',b'Command',1));path.chmod(0o444)
                return save(name,value)
            with patch.object(f,'save',intercepted),patch.object(g,'retire_result',side_effect=lambda *a,**kw:retired.append(True)):
                with self.assertRaises(ValueError):self.command(f)
            self.assertEqual(retired,[]);self.assertTrue(f.journal_failed)

    def test_unexpected_exit_is_committed_before_failure_and_raw_logs_retained(self):
        f,g,b,s,scope=self.fixture();b.code=3;b.output=b'actual rejection\r\n'
        with self.assertRaises(ValueError):f.sql(base.DATABASES[0],'unexpected','SELECT rejected;')
        journal=r.strict_json(s._verify(scope+'/owned-result-1.json'));self.assertEqual(journal[0]['returncode'],3)
        self.assertFalse(g.children[0].retired);self.assertTrue(g.children[0].stdout.is_file())
        self.assertTrue(g.finish_owner()['completed'])
        with self.assertRaises(ValueError):f.materialize_commands()

    def test_prior_history_mutation_and_noncontiguous_append_are_latched(self):
        for kind in ('entry','argv','list','append'):
            f,g,b,s,scope=self.fixture();self.command(f)
            with self.assertRaises(ValueError):
                if kind=='entry':f.events[0]['label']='changed'
                elif kind=='argv':f.events[0]['argv'].append('changed')
                elif kind=='list':f.events.pop()
                else:f.events.append(dict(id=3,label='bad',argv=[],stdout='',stderr='',returncode=0))
            self.assertTrue(f.journal_failed)
            with self.assertRaises(ValueError):self.command(f)

    def test_materialization_failure_is_after_finish_owner_and_repeated_calls_reject(self):
        f,g,b,s,scope=self.fixture();self.command(f);finished=[];finish=g.finish_owner;save=s.save
        def finishing():finished.append(True);return finish()
        def failing(name,value,**kwargs):
            if name=='commands.json':raise OSError('final history write failure')
            return save(name,value,**kwargs)
        with patch.object(g,'finish_owner',finishing),patch.object(s,'save',failing):
            try:self.assertEqual(len(f.journals),1)
            finally:g.finish_owner()
            with self.assertRaises(OSError):f.materialize_commands()
        self.assertEqual(finished,[True]);self.assertFalse(g.handlers_installed);self.assertTrue(f.journal_failed)

    def test_materialization_requires_finish_and_reconstructs_actual_committed_bytes(self):
        f,g,b,s,scope=self.fixture();self.command(f);g.cleanup()
        with self.assertRaises(ValueError):f.materialize_commands()
        f,g,b,s,scope=self.fixture();self.command(f);g.finish_owner()
        path=s.root/scope/'owned-result-1.json';path.chmod(0o600);path.write_bytes(b'[]\n');path.chmod(0o444)
        with self.assertRaises(ValueError):f.materialize_commands()

    def test_strict_rebound_records_reject_missing_duplicate_order_rawhash_sql_db_and_history(self):
        f,g,b,s,scope=self.fixture();f.sql(base.DATABASES[0],'sql','SELECT 1;');self.command(f)
        reader,meta=self.finish(f,g,s,scope)
        self.assertTrue(self.verify(reader,scope,meta))
        payload={name:reader.raw(name) for name,item in reader.index['files'].items() if '/' in name and item['role'] in ('alias','alias-bytes','mutable')}
        for kind in ('missing','duplicate','order','rawhash','sql','database','history','attestation','extra','numeric','path','argv'):
            values={name:(raw if name.endswith('.sql') else r.strict_json(raw)) for name,raw in payload.items()}
            key=scope+'/owned-result-1.json';cleanup=values[scope+'/case-cleanup.json']
            if kind=='missing':del values[key]
            elif kind=='duplicate':values[scope+'/owned-result-2.json'][0]['id']=1
            elif kind=='order':cleanup['commandJournal']['commands'].reverse()
            elif kind=='rawhash':values[key][1]['rawSha256']='0'*64
            elif kind=='sql':values[scope+'/sql-1.json']['sql']='SELECT 9;'
            elif kind=='database':values[scope+'/sql-1.json']['database']=base.DATABASES[1]
            elif kind=='history':values[scope+'/commands.json'][0]['label']='changed'
            elif kind=='attestation':cleanup['commandJournal']['commands'][0]['stdoutRawSha256']='0'*64
            elif kind=='extra':values[key][0]['extra']=True
            elif kind=='numeric':cleanup['commandJournal']['commands'][0]['retired']=1
            elif kind=='path':cleanup['commandJournal']['work']+='/changed'
            else:cleanup['commandJournal']['commands'][0]['argv'][-1]='--changed'
            new=r.EvidenceStore(self.root/('rebound-'+kind));new.scope(scope)
            # Preserve valid registered stdout references by copying exact gzip blobs via compact.
            for info in reader.index['blobs'].values():
                if info['kind']=='gzip':new.compact(reader.stdout(info['stdout']))
            for name,value in values.items():
                if name.endswith('.sql'):new.save_bytes(Path(name).name,value,scope=scope)
                else:new.save(Path(name).name,value,scope=scope)
            hashes=new.seal();other=r.EvidenceReader(new.root,expected_index_sha256=hashes['storage-index.json']);self.assertIs(other.validate(),True)
            with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError,OSError)):self.verify(other,scope,cleanup['commandJournal'])

    def test_final_metadata_rechecks_retained_child_object_without_result_reread(self):
        for kind in ('pid','exit','group','retired','known'):
            f,g,b,s,scope=self.fixture();self.command(f);g.finish_owner();f.materialize_commands();child=g.children[0]
            if kind=='pid':child.handle.pid+=1
            elif kind=='exit':child.exit_code=3
            elif kind=='group':child.group_quiet=False
            elif kind=='retired':child.retired=False
            else:g.children=[]
            with patch.object(g,'result',side_effect=AssertionError('retired logs must not reread')):
                with self.assertRaises(ValueError):f.command_journal_metadata()
            # Restore fake evidence for idempotent cleanup observer.
            if kind=='group':child.group_quiet=True

    def test_old_factory_remains_two_stream_and_staged_factory_is_optin_only(self):
        f,g,b,store,scope=self.fixture()
        old=h.fixture_class(helper,base,r)(g,{'toolchainRoot':str(f.pg.parents[4])},f.work,store.scope('old'),
            'pure',f.pg/'node',recording_store=store,recording_scope='old')
        # Old fixture's fixed pg path uses the same inert tool namespace.
        old.pg=f.pg
        old.command('version',[old.pg/'psql','--version'])
        self.assertEqual(len(r.strict_json(store._verify('old/owned-result-1.json'))),2)
        self.assertFalse(hasattr(old,'materialize_commands'))
        old_tree=ast.parse((Path('/Users/woro/Documents/Lomi/lomi-remote/artifacts/consumer-supervised5-journal-integration/a664365b-9fc5-477e-80d3-3063621ebd64/before-five/s5.py')).read_bytes());new_tree=ast.parse((HERE/'s5.py').read_bytes())
        funcs=lambda tree:{n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
        a,b=funcs(old_tree),funcs(new_tree)
        self.assertEqual(ast.dump(a['fixture_class']),ast.dump(b['fixture_class']))
        for name in ('verify_case','verify_sql_sources','cleanup_is_admissible','shared_budget_is_admissible','ordinary_receipts'):
            self.assertEqual(ast.dump(a[name]),ast.dump(b[name]))
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='journal_fixture_class' for n in ast.walk(b['fixture_class'])))

    def test_staged_run_cases_finishes_owner_before_shutdown_and_failed_materialization(self):
        node=next(n for n in ast.parse((HERE/'s5.py').read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name=='run_cases')
        namespace=dict(h.__dict__);events=[];work=self.root/'staged-work';work.mkdir(mode=0o700)
        class Owner:
            children=[]
            def __init__(self,*args,**kwargs):events.append('registered')
            def install(self):events.append('install')
            def finish_owner(self):events.append('finish_owner');return {'completed':True}
        class Fixture:
            def cleanup(self):events.append('cleanup')
            def save(self,name,value):events.append(name)
            def materialize_commands(self):
                events.append('materialize');raise OSError('injected materialization failure')
        fixture=Fixture()
        def make(g,*args,**kwargs):fixture.guardian=g;return fixture
        namespace.update(journal_fixture_class=lambda *args:make,
            load=lambda name,path:SimpleNamespace(CASES=[{'id':'pure'}]) if name=='admission_case_inventory' else SimpleNamespace(case_runner=lambda *args:lambda *args:None),
            tempfile=SimpleNamespace(mkdtemp=lambda **kwargs:str(work)),shutil=SimpleNamespace(disk_usage=lambda path:SimpleNamespace(free=3*1024**3)))
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<staged-run_cases>','exec'),namespace)
        base_fake=SimpleNamespace(NODE_HASH='f'*64,remaining_budget=lambda *args:None,require=lambda value,message:None if value else (_ for _ in ()).throw(ValueError(message)))
        pglock=dict(toolchainRoot='inert',toolchainCoreSha256={'Contents/Versions/18/bin/'+name:'a'*64 for name in ('postgres','initdb','pg_ctl','psql')},toolchainInitdbSha256={})
        store=SimpleNamespace(root=self.root,scope=lambda scope:self.root)
        pool=SimpleNamespace(view=lambda:SimpleNamespace(metadata=lambda:{}))
        guardian=SimpleNamespace(Executable=lambda *args:None,Guardian=Owner)
        with self.assertRaisesRegex(OSError,'materialization failure'):
            namespace['run_cases'](helper,frozen,base_fake,None,None,None,pglock,Path('/inert/node'),store,'pure',time.monotonic(),guardian,pool,r)
        self.assertEqual(events,['registered','install','cleanup','finish_owner','shutdown-clients.json','materialize'])

    def test_false_reader_and_metadata_type_closure_reject(self):
        f,g,b,s,scope=self.fixture();self.command(f);reader,metadata=self.finish(f,g,s,scope)
        with patch.object(reader,'validate',return_value=False):
            with self.assertRaisesRegex(ValueError,'reader incomplete'):self.verify(reader,scope,metadata)
        for field,value in [('version',1),('work',None),('repository',1),('commands',{})]:
            bad=copy.deepcopy(metadata);bad[field]=value
            with self.assertRaises((ValueError,TypeError)):self.verify(reader,scope,bad)

    def test_same_command_aliases_and_original_name_cap_fail_closed(self):
        f,g,b,s,scope=self.fixture()
        for n in range(3):self.command(f)
        g.finish_owner();f.materialize_commands()
        named={name for name in s.files if name.startswith(scope+'/')}
        self.assertEqual(named,{scope+'/owned-result-'+str(n)+'.json' for n in range(1,4)}|{scope+'/commands.json'})
        self.assertEqual(s.max_names,4096);self.assertEqual(s.max_bytes,256*1024**2)
        # Uniquecommand IDs intentionally prevent JSON-blob deduplication; do
        # not claim equal total indexed names versus the old two-stream form.
        self.assertEqual(len([name for name,item in s.files.items() if item['role']=='blob-json']),3)
        f,g,b,s,scope=self.fixture();s.max_names=16
        with self.assertRaises(ValueError):
            for n in range(20):self.command(f)
        self.assertTrue(s.incomplete);self.assertTrue(f.journal_failed)
        self.assertFalse(g.children[-1].retired);self.assertTrue(g.finish_owner()['completed'])
