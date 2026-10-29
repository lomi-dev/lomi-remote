"""Pure injected factory/clock/signal tests: never initialize Native or spawn OS children."""
from pathlib import Path
import ast
import hashlib
import importlib.util
import signal
import tempfile
import unittest
from unittest.mock import patch
s=importlib.util.spec_from_file_location('pg_guardian_pure',Path(__file__).with_name('guardian.py'));m=importlib.util.module_from_spec(s)
# dataclasses resolves annotations through sys.modules during module execution.
import sys
sys.modules[s.name]=m;s.loader.exec_module(m)
def deny_native(event,args):
    if event in {'subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','os.kill','os.killpg','ctypes.dlopen'}:
        raise AssertionError('pure-test audit blocked native operation: '+event)
sys.addaudithook(deny_native)
class Clock:
    def __init__(self):self.now=0
    def __call__(self):return self.now
    def sleep(self,amount):
        if amount<0:raise AssertionError('negative wait')
        self.now+=amount
class Signals:
    ITIMER_REAL=0
    def __init__(self):self.handlers={};self.timers=[]
    def getsignal(self,sig):return self.handlers.get(sig,'previous')
    def signal(self,sig,handler):self.handlers[sig]=handler
    def setitimer(self,which,value):self.timers.append(value)
    def deliver(self,sig):self.handlers[sig](sig,None)
class Handle:
    def __init__(self,pid,code):self.pid=pid;self.code=code;self.reaped=False;self.lost=False;self.members=[]
class Fake:
    test_only=True
    def __init__(self,clock):
        self.clock=clock;self.children=[];self.events=[];self.on_spawn=None;self.guardian=None
        self.output_sinks=[];self.node_live=False;self.stop_fails=False;self.stop_cancels=False;self.interrupt_stop=False;self.interrupted=False;self.ignore_kill=False
    def initialize(self):self.events.append(('initialize',))
    def spawn(self,argv,*,cwd,env,stdout,stderr):
        name=Path(argv[0]).name;g=self.guardian
        assert g.registered and g.marker_path.is_file()
        assert set(env)=={'PATH','HOME','TMPDIR','LANG','LC_ALL','TZ'}
        assert env['HOME']==str(g.work/'home') and env['TMPDIR']==str(g.work/'tmp')
        foreground=name=='postgres' and argv[-1]!='--version'
        code=None if foreground or name=='node' and self.node_live else 0
        self.output_sinks.append((name,stdout,stderr))
        if name=='pg_ctl' and argv[-1]=='status':code=3 if g.postgres and g.postgres.handle.code is not None else 0
        if name=='pg_ctl' and argv[-1]=='stop':
            if self.stop_cancels:
                for sig in m.CANCEL_SIGNALS:g.signals.deliver(sig)
            if self.stop_fails:code=1
            else:
                if g.postgres:g.postgres.handle.code=0;g.postgres.handle.members=[]
                (g.work/'data/postmaster.pid').unlink(missing_ok=True)
                for path in (g.work/'socket').iterdir():path.unlink()
        child=Handle(1000+len(self.children),code);self.children.append(child);self.events.append(('spawn',name,tuple(argv),child.pid))
        if foreground:
            (g.work/'data').mkdir(mode=0o700,exist_ok=True)
            (g.work/'data/postmaster.pid').write_text(str(child.pid)+'\n'+str(g.work/'data')+'\n0\n55439\n'+str(g.work/'socket')+'\n\n')
            (g.work/'socket/socket').write_text('fake')
        if self.on_spawn:self.on_spawn(name,child)
        return child
    def peek(self,handle):
        if handle not in self.children or handle.reaped or handle.lost:raise m.IdentityUnknown('fake ownership lost/reaped')
        if self.interrupt_stop and not self.interrupted and self.events[-1][0]=='spawn' and self.events[-1][1]=='pg_ctl':
            self.interrupted=True;raise InterruptedError('fake cleanup syscall interruption')
        return handle.code
    def signal_group(self,handle,sig):
        self.peek(handle);self.events.append(('signal',handle.pid,sig))
        if sig==signal.SIGKILL and not self.ignore_kill:handle.code=-9;handle.members=[]
    def other_live_group_members(self,handle):self.peek(handle);return list(handle.members)
    def reap(self,handle,timeout):
        self.peek(handle)
        if handle.code is None or handle.members:raise AssertionError('premature reap')
        handle.reaped=True;self.events.append(('reap',handle.pid));return handle.code
class GuardianTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='guardian-pure-');self.root=Path(self.temp.name).resolve();self.work=self.root/'work';self.work.mkdir(mode=0o700)
        self.tools={}
        for name in ('postgres','pg_ctl','initdb','psql','node'):
            path=self.root/name;path.write_text('inert pure fixture '+name);self.tools[name]=m.Executable(path,hashlib.sha256(path.read_bytes()).hexdigest())
        self.clock=Clock();self.signals=Signals();self.fake=Fake(self.clock)
        self.g=m.Guardian(self.work,self.tools,started=self.clock(),backend=self.fake,clock=self.clock,sleep=self.clock.sleep,signals=self.signals,run_id='pure-test')
        self.fake.guardian=self.g;self.g.install()
    def tearDown(self):
        self.g._emergency_sink.close() # Fake children only; real runner must finish_owner.
        self.temp.cleanup()
    def signals_sent(self):return [e for e in self.fake.events if e[0]=='signal']
    def test_registered_before_any_factory_and_closed_environment(self):
        self.assertEqual(self.fake.children,[]);self.g.initialize();self.assertTrue(self.g.children[0].reaped)
        self.assertTrue(self.g.cleanup()['completed']);self.g.restore_handlers();self.assertEqual(self.signals.timers[-1],0)
    def test_cancel_inside_spawn_before_registration_retains_then_stops_child(self):
        self.fake.node_live=True
        def cancel(name,child):
            self.assertFalse(any(r.handle is child for r in self.g.children))
            self.signals.deliver(signal.SIGTERM)
        self.fake.on_spawn=cancel
        with self.assertRaises(m.Cancelled):self.g.run_node('inert-script')
        self.assertEqual(len(self.g.children),1);self.assertTrue(self.g.children[0].reaped)
        self.assertEqual([e[2] for e in self.signals_sent()],[signal.SIGTERM,signal.SIGKILL])
        self.assertTrue(self.g.cleanup()['completed'])
    def test_cancel_during_foreground_startup_registers_pg_and_uses_real_stop_path(self):
        self.fake.on_spawn=lambda name,child:self.signals.deliver(signal.SIGINT) if name=='postgres' else None
        with self.assertRaises(m.Cancelled):self.g.start_postgres()
        self.assertIsNotNone(self.g.postgres);self.assertFalse(self.g.startup_confirmed)
        result=self.g.cleanup();self.assertTrue(result['completed']);self.assertTrue(result['postmasterNormalExit']);self.assertTrue(result['pgCtlStatusAbsent'])
        pg_commands=[e[2] for e in self.fake.events if e[0]=='spawn' and e[1]=='pg_ctl']
        self.assertEqual([a[-1] for a in pg_commands],['stop','status']);self.assertFalse(self.signals_sent())
    def test_repeated_cancellation_during_cleanup_cannot_unwind_cleanup(self):
        self.g.start_postgres();self.g.wait_startup();self.fake.stop_cancels=True
        result=self.g.cleanup();self.assertTrue(result['completed']);self.assertEqual(result['cancellationSignals'],list(m.CANCEL_SIGNALS));self.assertFalse(self.signals_sent())
    def test_interrupted_cleanup_is_unknown_and_never_discards_handles(self):
        self.g.start_postgres();self.fake.interrupt_stop=True
        result=self.g.cleanup();self.assertFalse(result['completed']);self.assertEqual(result['status'],'UNKNOWN');self.assertTrue(result['privateWorkRetained']);self.assertTrue(self.g.marker_path.exists());self.assertTrue(result['errors'])
        with self.assertRaises(m.IdentityUnknown):self.g.restore_handlers()
    def test_never_signal_reaped_unowned_or_lost_identity(self):
        record=self.g.run_node('inert-script');count=len(self.signals_sent())
        with self.assertRaises(m.IdentityUnknown):self.g._signal(record,signal.SIGKILL)
        clone=m.Child(record.handle,record.name,record.argv,record.stdout,record.stderr)
        with self.assertRaises(m.IdentityUnknown):self.g._signal(clone,signal.SIGKILL)
        outsider=m.Child(Handle(17253,None),'unowned',(),self.work/'none',self.work/'none')
        with self.assertRaises(m.IdentityUnknown):self.g._signal(outsider,signal.SIGKILL)
        self.assertEqual(len(self.signals_sent()),count)
        self.fake.node_live=True;live=self.g._launch('node',['inert']);live.handle.lost=True
        result=self.g.cleanup();self.assertFalse(result['completed']);self.assertFalse(live.reaped);self.assertEqual(len(self.signals_sent()),count)
    def test_pidfile_cannot_authorize_unowned_pid(self):
        self.g.start_postgres();path=self.work/'data/postmaster.pid';path.write_text(path.read_text().replace(str(self.g.postgres.handle.pid)+'\n','17253\n',1))
        result=self.g.cleanup();self.assertFalse(result['completed'])
        self.assertFalse(any(e[0]=='spawn' and e[1]=='pg_ctl' for e in self.fake.events))
        self.assertTrue(all(e[1]!=17253 for e in self.signals_sent()))
    def test_original900_expiry_still_allows_owned_cleanup_until960(self):
        self.g.start_postgres();self.clock.now=901
        result=self.g.cleanup();self.assertTrue(result['completed']);self.assertTrue(self.g.postgres.reaped);self.assertTrue(result['privateWorkRetained']);self.assertFalse(result['qualificationEligible']);self.assertTrue(result['qualificationDeadlineExpired'])
    def test_work840_reserves_cleanup_inside_original900(self):
        self.g.start_postgres();self.clock.now=841
        with self.assertRaises(m.BudgetExpired):self.g.checkpoint()
        self.assertEqual(self.g.checkpoint(cleanup=True),119)
        self.assertTrue(self.g.cleanup()['completed']);self.assertLess(self.clock.now,900)
    def test_original_start_is_not_renewed_on_guardian_construction(self):
        other=self.root/'original-budget';other.mkdir(mode=0o700);clock=Clock();clock.now=839;backend=Fake(clock);signals=Signals()
        guardian=m.Guardian(other,self.tools,started=0,backend=backend,clock=clock,sleep=clock.sleep,signals=signals,run_id='original')
        backend.guardian=guardian;guardian.install();self.assertEqual(guardian.remaining(),1)
        clock.now=841
        with self.assertRaises(m.BudgetExpired):guardian.initialize()
        self.assertFalse(backend.children);self.assertTrue(guardian.cleanup()['completed'])
    def test_late_factory_return_registers_then_reaps_inside_emergency_budget(self):
        self.fake.node_live=True;self.fake.on_spawn=lambda name,child:setattr(self.clock,'now',901)
        with self.assertRaises(m.BudgetExpired):self.g.run_node('inert')
        self.assertEqual(len(self.g.children),1);self.assertTrue(self.g.children[0].reaped)
        result=self.g.cleanup();self.assertTrue(result['completed']);self.assertFalse(result['qualificationEligible'])
    def test_group_anchor_remains_unreaped_through_kill_and_worker_quiescence(self):
        self.fake.node_live=True;record=self.g._launch('node',['inert']);record.handle.members=[2001,2002]
        self.g._stop(record);self.assertTrue(record.reaped);self.assertTrue(record.group_quiet)
        events=[e[0] for e in self.fake.events if e[0] in ('signal','reap')];self.assertEqual(events,['signal','signal','reap'])
    def test_stubborn_group_cannot_qualify_cleanup(self):
        self.fake.node_live=True;self.fake.ignore_kill=True;record=self.g._launch('node',['inert']);record.handle.members=[2001]
        result=self.g.cleanup();self.assertFalse(result['completed']);self.assertFalse(record.reaped);self.assertLess(self.clock.now,5)
    def test_forced_postgres_stop_never_claims_worker_cleanup(self):
        self.g.start_postgres();self.fake.stop_fails=True
        result=self.g.cleanup();self.assertFalse(result['completed']);self.assertTrue(self.g.postgres.forced);self.assertTrue(result['privateWorkRetained'])
    def test_evidence_open_failure_cannot_skip_retained_pg_cleanup(self):
        self.g.start_postgres()
        # Exclusive evidence creation fails, but the preopened sink survives.
        (self.work/'logs/child-2.stdout').write_text('existing evidence')
        result=self.g.cleanup();self.assertTrue(result['completed']);self.assertTrue(self.g.postgres.reaped);self.assertFalse(self.g.postgres.forced)
        self.assertFalse(result['qualificationEligible']);self.assertTrue(any('FileExistsError' in error for error in result['evidenceErrors']))
        self.assertEqual([e[2][-1] for e in self.fake.events if e[0]=='spawn' and e[1]=='pg_ctl'],['stop','status'])
        self.assertEqual((self.work/'logs/child-2.stdout').read_text(),'existing evidence')
    def test_evidence_close_error_after_spawn_still_registers_foreground_pg(self):
        original=Path.open
        class BrokenClose:
            def __init__(self,file):self.file=file
            def __enter__(self):return self.file
            def __exit__(self,*args):self.file.close();raise OSError('injected evidence close failure')
        def injected(path,*args,**kwargs):
            file=original(path,*args,**kwargs)
            return BrokenClose(file) if path.name=='child-1.stderr' and args==('xb',) else file
        with patch.object(Path,'open',injected):
            with self.assertRaises(OSError):self.g.start_postgres()
        self.assertEqual(len(self.g.children),1);self.assertIs(self.g.postgres,self.g.children[0]);self.assertFalse(self.g.postgres.reaped)
        self.assertTrue(self.g.cleanup()['completed'])
    def test_pg_ctl_reply_cannot_bless_postmaster_still_live(self):
        self.g.start_postgres()
        def keep_alive(name,child):
            if name=='pg_ctl':
                self.g.postgres.handle.code=None
                if self.fake.events[-1][2][-1]=='status':child.code=3
        self.fake.on_spawn=keep_alive
        result=self.g.cleanup();self.assertFalse(result['completed']);self.assertFalse(result['postmasterNormalExit']);self.assertTrue(self.g.postgres.forced)
    def test_short_child_execution_bound_uses_reserved_owned_cleanup(self):
        self.fake.node_live=True
        with self.assertRaises(m.BudgetExpired):self.g.run_node('inert')
        self.assertGreaterEqual(self.clock.now,60);self.assertLess(self.clock.now,63)
        self.assertTrue(self.g.children[0].reaped);self.assertTrue(self.g.cleanup()['completed'])
    def test_nonraising_latch_deduplicates_repeated_signals(self):
        for _ in range(20):
            for sig in m.CANCEL_SIGNALS:self.signals.deliver(sig)
        self.assertEqual(self.g.cancel.signals,list(m.CANCEL_SIGNALS))
        self.assertTrue(self.g.cleanup()['completed'])
    def test_pinned_tool_or_marker_substitution_starts_no_child(self):
        self.tools['node'].path.write_text('changed')
        with self.assertRaises(ValueError):self.g.run_node('inert')
        self.assertFalse(self.fake.children)
        self.g.marker_path.write_text('changed')
        with self.assertRaises(m.IdentityUnknown):self.g.initialize()
        self.assertFalse(self.fake.children);self.assertFalse(self.g.cleanup()['completed'])
    def test_context_always_cleans_and_retains_work(self):
        # New context on the already-installed guardian is intentionally invalid.
        with self.assertRaises(RuntimeError):self.g.__enter__()
        self.g.start_postgres();self.g.__exit__(RuntimeError,RuntimeError('fixture failed'),None)
        self.assertTrue(self.g.cleanup_result['completed']);self.assertTrue(self.work.exists());self.assertFalse(self.g.handlers_installed)
    def test_completed_cleanup_is_idempotent_and_work_cannot_restart(self):
        self.g.start_postgres();first=self.g.cleanup();events=list(self.fake.events)
        self.assertTrue(first['completed']);self.assertEqual(self.g.cleanup(),first);self.assertEqual(events,self.fake.events)
        with self.assertRaises(RuntimeError):self.g.run_node('inert')
        self.g.restore_handlers()
        with self.assertRaises(RuntimeError):self.g.install()
    def test_psql_restricts_database_and_owned_file(self):
        sql=self.work/'case.sql';sql.write_text('inert')
        with self.assertRaises(ValueError):self.g.psql('production',sql)
        with self.assertRaises(ValueError):self.g.psql('postgres',self.root/'node')
        self.g.psql('postgres',sql);self.assertTrue(self.g.cleanup()['completed'])
    def test_darwin_group_inventory_requires_retained_anchor(self):
        raw=bytes((m.ctypes.c_int*3)(1000,2001,2002))
        self.assertEqual(m.darwin_group_inventory(raw,len(raw),4096,1000),[1000,2001,2002])
        lone=bytes((m.ctypes.c_int*1)(1000));self.assertEqual(m.darwin_group_inventory(lone,len(lone),4096,1000),[1000])
        for count in (0,-1,3,4096,8192):
            with self.subTest(count=count),self.assertRaises(m.IdentityUnknown):m.darwin_group_inventory(raw,count,4096,1000)
        for pids in ((2001,2002),(1000,1000),(1000,0),(1000,-1)):
            raw=bytes((m.ctypes.c_int*len(pids))(*pids))
            with self.subTest(pids=pids),self.assertRaises(m.IdentityUnknown):m.darwin_group_inventory(raw,len(raw),4096,1000)
    def test_raw_log_boundary_is_explicitly_schema_fixture_only(self):
        self.assertIn('ONLY for public/schema fixtures',m.__doc__)
        self.assertIn('Do not use this raw-log',m.__doc__)
        self.assertIn('private parser-worker and closed-pipe seam',m.__doc__)
    def test_late_foreground_popen_return_uses_emergency_cleanup_not_qualification(self):
        self.fake.on_spawn=lambda name,child:setattr(self.clock,'now',901) if name=='postgres' else None
        with self.assertRaises(m.BudgetExpired):self.g.start_postgres()
        self.assertIsNotNone(self.g.postgres);self.assertFalse(self.g.postgres.reaped)
        result=self.g.finish_owner();self.assertTrue(result['completed']);self.assertFalse(result['qualificationEligible'])
        self.assertTrue(result['postmasterNormalExit']);self.assertTrue(self.g.postgres.reaped)
        self.assertEqual(result['originalQualificationDeadline'],900);self.assertEqual(result['emergencyCleanupDeadline'],960)
        self.assertFalse(self.g.terminal_retention)
    def test_qualification_cutoff_is_irrevocable_without_resetting_emergency_budget(self):
        self.g.start_postgres();self.clock.now=900
        result=self.g.cleanup();self.assertTrue(result['completed']);self.assertFalse(result['qualificationEligible'])
        self.clock.now=890
        again=self.g.cleanup();self.assertFalse(again['qualificationEligible']);self.assertTrue(again['qualificationDeadlineExpired'])
        self.assertEqual(self.g.emergency_deadline,960)
    def test_past960_context_enters_terminal_retention_and_cannot_return(self):
        class RetainedForPureTest(BaseException):pass
        self.fake.node_live=True;self.fake.on_spawn=lambda name,child:setattr(self.clock,'now',961)
        with self.assertRaises(m.BudgetExpired):self.g.run_node('inert')
        self.assertFalse(self.g.children[0].reaped);before=list(self.fake.events)
        reports=[]
        def observer(report):reports.append(report);raise OSError('failure receipt write unavailable')
        def test_hold(guardian,report):
            self.assertTrue(guardian.terminal_retention);self.assertTrue(report['ownerRetained']);self.assertFalse(report['qualificationEligible'])
            self.assertEqual(guardian.emergency_deadline,960);raise RetainedForPureTest()
        self.g.terminal_observer=observer;self.g._test_terminal_hook=test_hold
        with self.assertRaises(RetainedForPureTest):self.g.__exit__(None,None,None)
        self.assertTrue(reports);self.assertEqual(self.fake.events,before);self.assertFalse(self.g.children[0].reaped)
        self.assertTrue(self.g.handlers_installed);self.assertFalse(self.g._emergency_sink.closed)
        with self.assertRaises(RuntimeError):self.g.run_node('inert')
    def test_terminal_test_escape_cannot_be_injected_into_native_owner(self):
        work=self.root/'reject-native-hook';work.mkdir(mode=0o700)
        with self.assertRaises(ValueError):m.Guardian(work,self.tools,started=0,_test_terminal_hook=lambda *_:None)
    def test_eperm_zombie_only_group_requires_complete_owned_proof(self):
        self.fake.node_live=True;record=self.g._launch('node',['inert']);record.handle.code=-15
        sent=[]
        def permission(pid,sig):sent.append((pid,sig));raise PermissionError('fake Darwin zombie EPERM')
        m.signal_retained_group(self.fake,record.handle,signal.SIGKILL,permission)
        self.assertEqual(sent,[(record.handle.pid,signal.SIGKILL)]);self.assertFalse(record.reaped)
        record.handle.code=None
        with self.assertRaises(PermissionError):m.signal_retained_group(self.fake,record.handle,signal.SIGKILL,permission)
        record.handle.code=-15;record.handle.members=[2001]
        with self.assertRaises(PermissionError):m.signal_retained_group(self.fake,record.handle,signal.SIGKILL,permission)
        record.handle.members=[]
        with patch.object(self.fake,'other_live_group_members',side_effect=m.IdentityUnknown('ambiguous zero inventory')):
            with self.assertRaises(m.IdentityUnknown):m.signal_retained_group(self.fake,record.handle,signal.SIGKILL,permission)
        record.handle.lost=True;count=len(sent)
        with self.assertRaises(m.IdentityUnknown):m.signal_retained_group(self.fake,record.handle,signal.SIGKILL,permission)
        self.assertEqual(count,len(sent))
    def test_full_or_unwritable_fresh_logs_do_not_block_stop_status(self):
        self.g.start_postgres();original=Path.open
        def unavailable(path,*args,**kwargs):
            if path.parent==self.work/'logs' and args==('xb',):raise OSError(28,'injected full evidence filesystem')
            return original(path,*args,**kwargs)
        with patch.object(Path,'open',unavailable):result=self.g.cleanup()
        self.assertTrue(result['completed']);self.assertTrue(result['postmasterNormalExit']);self.assertTrue(result['pgCtlStatusAbsent'])
        self.assertFalse(result['qualificationEligible']);self.assertTrue(result['evidenceErrors'])
        clients=[r for r in self.g.children if r.name=='pg_ctl'];self.assertEqual([r.exit_code for r in clients],[0,3])
        for record in clients:
            output=self.g.result(record);self.assertEqual(output.returncode,record.exit_code);self.assertFalse(output.evidenceComplete);self.assertEqual(output.stdout,'');self.assertEqual(output.stderr,'')
        self.assertTrue(all(out is self.g._emergency_sink and err is self.g._emergency_sink for name,out,err in self.fake.output_sinks if name=='pg_ctl'))
    def test_reserved_discard_sink_is_open_before_first_child_and_never_reopened(self):
        self.assertFalse(self.g._emergency_sink.closed);self.assertEqual(len(self.fake.children),0)
        self.g.start_postgres();original_open=m.os.open;original_path_open=Path.open
        def unavailable_sink(path,*args,**kwargs):
            if str(path)==m.os.devnull:raise PermissionError('no new sink open allowed')
            return original_open(path,*args,**kwargs)
        def unavailable_log(path,*args,**kwargs):
            if path.parent==self.work/'logs' and args==('xb',):raise PermissionError('fresh logs unwritable')
            return original_path_open(path,*args,**kwargs)
        with patch.object(m.os,'open',unavailable_sink),patch.object(Path,'open',unavailable_log):result=self.g.cleanup()
        self.assertTrue(result['completed']);self.assertFalse(result['qualificationEligible']);self.assertFalse(self.g.postgres.forced)
    def test_version_role_never_registers_persistent_postmaster(self):
        version=self.g.tool_version('postgres');self.assertTrue(version.reaped);self.assertFalse(version.foreground);self.assertIsNone(self.g.postgres)
        self.assertEqual(self.g.result(version).returncode,0)
        self.g.start_postgres();self.assertTrue(self.g.postgres.foreground);self.assertTrue(self.g.cleanup()['completed'])
        with self.assertRaises(ValueError):self.g.tool_version('unknown')
    def test_public_result_is_bounded_and_preserves_universal_newline_blanks(self):
        record=self.g.run_node('inert');record.stdout.write_bytes(b'\r\nA\r\n\r\nB\r')
        result=self.g.result(record,max_bytes=32);self.assertEqual(result.stdout,'\nA\n\nB\n');self.assertTrue(result.evidenceComplete)
        clone=m.Child(record.handle,record.name,record.argv,record.stdout,record.stderr)
        with self.assertRaises(m.IdentityUnknown):self.g.result(clone)
        with self.assertRaises(ValueError):self.g.result(record,max_bytes=32*1024**2+1)
        with self.assertRaises(ValueError):self.g.result(record,max_bytes=True)
        with self.assertRaises(ValueError):self.g.result(record,max_bytes=2)
        self.fake.node_live=True;live=self.g._launch('node',['inert'])
        with self.assertRaises(m.IdentityUnknown):self.g.result(live)
    def test_public_result_rejects_invalid_utf8_and_oversize_before_read(self):
        record=self.g.run_node('inert');record.stdout.write_bytes(b'\xff')
        with self.assertRaises(UnicodeDecodeError):self.g.result(record)
        self.assertTrue(self.g.evidence_errors);self.assertTrue(self.g.unqualified)
        record.stdout.write_bytes(b'oversize');original=Path.open;reads=[]
        def audit_read(path,*args,**kwargs):
            if path==record.stdout and args==('rb',):reads.append(path)
            return original(path,*args,**kwargs)
        with patch.object(Path,'open',audit_read):
            with self.assertRaises(ValueError):self.g.result(record,max_bytes=2)
        self.assertEqual(reads,[])
    def test_audit_hook_denies_native_actions_before_execution(self):
        for event in ('subprocess.Popen','os.fork','os.killpg','ctypes.dlopen'):
            with self.subTest(event=event),self.assertRaises(AssertionError):sys.audit(event,'pure audit event only')
    def test_cancel_before_pidfile_creation_waits_bounded_identity_grace_then_stops(self):
        pending={}
        def cancel_before_pidfile(name,child):
            if name=='postgres':
                path=self.work/'data/postmaster.pid';pending['identity']=path.read_text();path.unlink()
                for path in (self.work/'socket').iterdir():path.unlink()
                self.signals.deliver(signal.SIGTERM)
        self.fake.on_spawn=cancel_before_pidfile
        with self.assertRaises(m.Cancelled):self.g.start_postgres()
        def publish_on_sleep(amount):
            self.clock.sleep(amount)
            if self.clock.now>=.05 and not (self.work/'data/postmaster.pid').exists():
                (self.work/'data/postmaster.pid').write_text(pending['identity'])
        self.g.sleep=publish_on_sleep
        result=self.g.finish_owner();self.assertTrue(result['completed']);self.assertFalse(result['qualificationEligible'])
        self.assertTrue(result['postmasterNormalExit']);self.assertFalse(self.g.postgres.forced);self.assertFalse(self.g.terminal_retention)
        self.assertLess(self.clock.now,5);self.assertEqual([e[2][-1] for e in self.fake.events if e[0]=='spawn' and e[1]=='pg_ctl'],['stop','status'])
    def test_wrong_or_malformed_startup_identity_never_authorizes_pg_ctl(self):
        self.g.start_postgres();(self.work/'data/postmaster.pid').write_text('malformed wrong PID')
        result=self.g.cleanup();self.assertFalse(result['completed']);self.assertTrue(result['ownershipUnresolved'])
        self.assertGreaterEqual(self.clock.now,5);self.assertLess(self.clock.now,6)
        self.assertFalse(any(e[0]=='spawn' and e[1]=='pg_ctl' for e in self.fake.events));self.assertTrue(self.g.postgres.forced)
    def test_startup_child_exit_without_pid_cannot_bless_absence(self):
        self.g.start_postgres();(self.work/'data/postmaster.pid').unlink();self.g.postgres.handle.code=0
        result=self.g.cleanup();self.assertFalse(result['completed']);self.assertTrue(result['ownershipUnresolved'])
        self.assertFalse(result['postmasterNormalExit']);self.assertFalse(any(e[0]=='spawn' and e[1]=='pg_ctl' for e in self.fake.events))
    def test_startup_identity_grace_never_renews_emergency_deadline(self):
        self.g.start_postgres();(self.work/'data/postmaster.pid').unlink();self.clock.now=959.95
        result=self.g.cleanup();self.assertFalse(result['completed']);self.assertFalse(self.g.postgres.reaped)
        self.assertGreaterEqual(self.clock.now,960);self.assertEqual(self.g.emergency_deadline,960);self.assertFalse(self.signals_sent())
    def test_native_and_native_subclass_cannot_claim_fake_test_escape(self):
        class PretendFakeNative(m.Native):test_only=True
        for index,kind in enumerate((m.Native,PretendFakeNative)):
            backend=kind.__new__(kind);backend.test_only=True
            work=self.root/('native-spoof-'+str(index));work.mkdir(mode=0o700)
            with self.subTest(kind=kind.__name__),self.assertRaises(ValueError):
                m.Guardian(work,self.tools,started=0,backend=backend,_test_terminal_hook=lambda *_:None)
    def test_late_native_hook_is_ignored_reported_and_terminal_loop_continues(self):
        class PretendFakeNative(m.Native):test_only=True
        class PureClockLoopObserved(BaseException):pass
        for kind in (m.Native,PretendFakeNative):
            backend=kind.__new__(kind);backend.test_only=True;self.g.terminal_retention=False
            self.g.backend=backend;calls=[];reports=[];clock_calls=[]
            def invalid_hook(*args):calls.append(args);raise AssertionError('Native escape hook must not execute')
            def inert_cleanup():
                self.g.cleanup_result=dict(ownershipUnresolved=True,completed=False,qualificationEligible=False)
                return self.g.cleanup_result
            def observe_loop_clock():
                clock_calls.append(1)
                if len(clock_calls)>=4:raise PureClockLoopObserved('pure harness observes second holding cycle')
                return 961
            self.g._test_terminal_hook=invalid_hook;self.g.cleanup=inert_cleanup;self.g.clock=observe_loop_clock;self.g.terminal_observer=reports.append
            with self.assertRaises(PureClockLoopObserved):self.g.finish_owner()
            self.assertEqual(calls,[]);self.assertTrue(self.g.terminal_retention);self.assertTrue(self.g.handlers_installed)
            self.assertGreaterEqual(len(reports),2);self.assertEqual(reports[-1]['invalidTestHook'],'native-or-unmarked-backend test hook ignored')
            self.assertEqual(reports[-1]['status'],'TERMINAL_OWNER_RETAINED_UNQUALIFIED');self.assertFalse(reports[-1]['qualificationEligible'])
    def test_native_is_source_only_and_launch_is_inside_try(self):
        tree=ast.parse(Path(m.__file__).read_text());launch=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='_launch')
        guarded=[n for n in ast.walk(launch) if isinstance(n,ast.Try)]
        self.assertTrue(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='spawn' for block in guarded for statement in block.body for n in ast.walk(statement)))
        self.assertFalse(any(e[0]=='spawn' for e in self.fake.events))
if __name__=='__main__':unittest.main()
