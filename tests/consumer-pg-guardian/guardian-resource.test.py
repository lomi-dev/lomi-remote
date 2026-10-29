"""Optional raw-log policy integration: real policy, fake limits/processes only."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
POLICY_SHA='1d631ec27f30f7b969ed32ab4504300a8932123401b0d5713a65b3a84a53cb3e'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
# Reuse the43 audited fake-backend suite; importing it installs the native-deny
# audit hook but executes no tests/processes. Native helpers are never invoked.
core=load('guardian_resource_core',HERE/'guardian.test.py');m=core.m
path=ROOT/'tests/consumer-derivatives-v2-s5-pre012-supervised/resource_policy.py'
if hashlib.sha256(path.read_bytes()).hexdigest()!=POLICY_SHA:raise ValueError('source-admitted resource policy changed')
r=load('guardian_resource_policy',path)
class Limits:
    RLIMIT_FSIZE=1
    def __init__(self):self.limit=(-1,-1);self.events=[]
    def setrlimit(self,kind,value):self.events.append(('install',kind,value));self.limit=value
    def getrlimit(self,kind):return self.limit
class FileSignals:
    SIGXFSZ=25
    SIG_IGN=1
    def __init__(self,disposition=1):self.disposition=disposition
    def getsignal(self,signum):return self.disposition
class BudgetBackend(core.Fake):
    def initialize(self):
        assert self.guardian.log_policy.installed
        assert self.guardian.log_policy.resource_api.getrlimit(1)==(r.STREAM_BYTES,r.STREAM_BYTES)
        super().initialize()
class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='guardian-resource-pure-');self.root=Path(self.temp.name).resolve();self.work=self.root/'work';self.work.mkdir(mode=0o700)
        self.tools={}
        for name in ('postgres','pg_ctl','initdb','psql','node'):
            file=self.root/name;file.write_text('inert pure fixture '+name);self.tools[name]=m.Executable(file,hashlib.sha256(file.read_bytes()).hexdigest())
        self.clock=core.Clock();self.signals=core.Signals();self.backend=BudgetBackend(self.clock);self.limits=Limits();self.file_signals=FileSignals();self.policy=r.ResourcePolicy(resource_api=self.limits,signal_api=self.file_signals)
        self.g=m.Guardian(self.work,self.tools,started=0,backend=self.backend,clock=self.clock,sleep=self.clock.sleep,signals=self.signals,log_policy=self.policy,run_id='resource-pure')
        self.backend.guardian=self.g;self.g.install()
    def tearDown(self):self.g._emergency_sink.close();self.temp.cleanup()
    def output(self,name,child):
        out,err=self.backend.output_sinks[-1][1:];out.write(b'public\r\n\n');out.flush();err.write(b'fixture\n');err.flush()
    def fill_normal(self):
        self.g.start_postgres()
        return [self.g.run_node('inert') for _ in range(5)]
    def test_prepare_and_fixed_cap_install_precede_every_child(self):
        self.assertTrue(self.policy.prepared);self.assertTrue(self.policy.installed);self.assertEqual(len(self.backend.children),0)
        self.assertEqual(self.limits.events,[('install',1,(32*1024**2,32*1024**2))])
        self.g.run_node('inert');self.assertEqual(self.policy.metadata()['currentReservedBytes'],64*1024**2)
        self.assertTrue(all((p.stat().st_mode&0o777)==0o600 for p in (self.work/'logs').iterdir()))
    def test_raw_hashes_precede_newline_decode_and_verified_recording_retirement(self):
        self.backend.on_spawn=self.output;child=self.g.run_node('inert');result=self.g.result(child)
        self.assertEqual(result.stdout,'public\n\n');self.assertEqual(result.stdoutSha256,hashlib.sha256(b'public\r\n\n').hexdigest())
        self.assertEqual(result.stderrSha256,hashlib.sha256(b'fixture\n').hexdigest())
        # The caller commits exact returned data+original hashes before retiring.
        (self.work/'committed-compact.json').write_text(json.dumps(dict(stdout=result.stdout,stderr=result.stderr,stdoutSha256=result.stdoutSha256,stderrSha256=result.stderrSha256)))
        self.assertTrue(self.g.retire_result(child,stdout_sha256=result.stdoutSha256,stderr_sha256=result.stderrSha256))
        self.assertTrue(child.retired);self.assertFalse(child.stdout.exists());self.assertFalse(child.stderr.exists());self.assertEqual(self.policy.tokens,{})
        with self.assertRaises(m.IdentityUnknown):self.g.result(child)
    def test_both_hashes_must_match_before_either_unlink(self):
        self.backend.on_spawn=self.output;child=self.g.run_node('inert');result=self.g.result(child)
        with self.assertRaises(m.IdentityUnknown):self.g.retire_result(child,stdout_sha256=result.stdoutSha256,stderr_sha256='0'*64)
        self.assertTrue(child.stdout.exists());self.assertTrue(child.stderr.exists());self.assertFalse(child.retired);self.assertEqual(len(self.policy.tokens),1);self.assertTrue(self.g.unqualified)
    def test_equal_bytes_on_replacement_inode_cannot_retire_or_read(self):
        child=self.g.run_node('inert');result=self.g.result(child);replacement=self.work/'replacement';replacement.write_bytes(child.stdout.read_bytes());replacement.replace(child.stdout)
        with self.assertRaises(m.IdentityUnknown):self.g.retire_result(child,stdout_sha256=result.stdoutSha256,stderr_sha256=result.stderrSha256)
        with self.assertRaises(m.IdentityUnknown):self.g.result(child)
        self.assertTrue(child.stdout.exists());self.assertTrue(child.stderr.exists());self.assertEqual(len(self.policy.tokens),1)
    def test_foreground_unreaped_and_unknown_retirement_are_rejected(self):
        pg=self.g.start_postgres();empty=hashlib.sha256(b'').hexdigest()
        with self.assertRaises(m.IdentityUnknown):self.g.retire_result(pg,stdout_sha256=empty,stderr_sha256=empty)
        self.backend.node_live=True;live=self.g._launch('node',['inert'])
        with self.assertRaises(m.IdentityUnknown):self.g.retire_result(live,stdout_sha256=empty,stderr_sha256=empty)
        clone=m.Child(live.handle,live.name,live.argv,live.stdout,live.stderr)
        with self.assertRaises(m.IdentityUnknown):self.g.retire_result(clone,stdout_sha256=empty,stderr_sha256=empty)
    def test_aggregate_exhaustion_stops_work_but_preserves_cleanup_reserve(self):
        self.fill_normal();before=len(self.backend.children)
        self.assertEqual(self.policy.metadata()['currentReservedBytes'],384*1024**2)
        with self.assertRaises(r.ResourceLimit):self.g.run_node('inert-no-budget')
        self.assertEqual(len(self.backend.children),before);self.assertTrue(self.g.unqualified)
        cleanup=self.g.finish_owner();self.assertTrue(cleanup['completed']);self.assertFalse(cleanup['qualificationEligible']);self.assertTrue(cleanup['postmasterNormalExit'])
        self.assertEqual([c.exit_code for c in self.g.children if c.name=='pg_ctl'],[0,3]);self.assertEqual(self.policy.metadata()['highWaterReservedBytes'],512*1024**2)
    def test_full_cleanup_reserve_uses_preopened_discard_with_actual_exit_facts(self):
        self.fill_normal()
        for index in range(2):self.policy.reserve('reserved-cleanup',self.work/'logs'/('reserved-'+str(index)+'.out'),self.work/'logs'/('reserved-'+str(index)+'.err'),cleanup=True)
        self.assertEqual(self.policy.metadata()['currentReservedBytes'],512*1024**2)
        result=self.g.finish_owner();self.assertTrue(result['completed']);self.assertFalse(result['qualificationEligible']);self.assertTrue(result['evidenceErrors'])
        clients=[c for c in self.g.children if c.name=='pg_ctl'];self.assertEqual([c.exit_code for c in clients],[0,3]);self.assertTrue(all(c.evidence_fallback for c in clients))
        self.assertTrue(all(self.g.result(c).evidenceComplete is False for c in clients));self.assertFalse(self.g.postgres.forced)
    def test_retirement_restores_admission_without_retaining_raw_text(self):
        records=self.fill_normal();child=records[0];result=self.g.result(child)
        self.g.retire_result(child,stdout_sha256=result.stdoutSha256,stderr_sha256=result.stderrSha256)
        self.assertEqual(self.policy.metadata()['currentReservedBytes'],320*1024**2)
        admitted=self.g.run_node('inert');self.assertTrue(admitted.reaped);self.assertEqual(self.policy.metadata()['currentReservedBytes'],384*1024**2)
        self.assertTrue(child.retired);self.assertIsNone(getattr(self.g,'last_result',None))
    def test_cancel_at_launch_with_budget_still_stops_registered_child(self):
        self.backend.node_live=True;self.backend.on_spawn=lambda name,child:self.signals.deliver(m.signal.SIGTERM)
        with self.assertRaises(m.Cancelled):self.g.run_node('inert')
        self.assertEqual(len(self.policy.tokens),1);self.assertTrue(self.g.children[0].reaped)
        result=self.g.finish_owner();self.assertTrue(result['completed']);self.assertFalse(result['qualificationEligible'])
    def test_changed_hard_limit_stops_work_cleanup_falls_back_without_new_cap_claim(self):
        self.g.start_postgres();self.limits.limit=(64*1024**2,64*1024**2);before=len(self.backend.children)
        with self.assertRaises(r.ResourceLimit):self.g.run_node('inert')
        self.assertEqual(len(self.backend.children),before)
        result=self.g.finish_owner();self.assertTrue(result['completed']);self.assertFalse(result['qualificationEligible']);self.assertTrue(all(c.evidence_fallback for c in self.g.children if c.name=='pg_ctl'))
    def test_release_error_after_verified_unlink_never_blocks_physical_pg_cleanup(self):
        self.g.start_postgres();child=self.g.run_node('inert');result=self.g.result(child)
        with patch.object(self.policy,'release',side_effect=r.ResourceLimit('injected debit failure')):
            with self.assertRaises(r.ResourceLimit):self.g.retire_result(child,stdout_sha256=result.stdoutSha256,stderr_sha256=result.stderrSha256)
        self.assertTrue(child.retired);self.assertFalse(child.stdout.exists());self.assertFalse(child.stderr.exists())
        cleanup=self.g.finish_owner();self.assertTrue(cleanup['completed']);self.assertFalse(cleanup['qualificationEligible']);self.assertTrue(cleanup['postmasterNormalExit'])
    def test_double_retirement_cannot_release_a_different_reservation(self):
        first=self.g.run_node('first');second=self.g.run_node('second');result=self.g.result(first)
        self.g.retire_result(first,stdout_sha256=result.stdoutSha256,stderr_sha256=result.stderrSha256)
        with self.assertRaises(m.IdentityUnknown):self.g.retire_result(first,stdout_sha256=result.stdoutSha256,stderr_sha256=result.stderrSha256)
        self.assertEqual(len(self.policy.tokens),1);self.assertIs(next(iter(self.policy.tokens.values())),second.log_token)
    def test_malformed_hash_cannot_delete_evidence_or_debit(self):
        child=self.g.run_node('inert');result=self.g.result(child)
        for value in (None,False,'','G'*64,'0'*63):
            with self.subTest(value=value),self.assertRaises(ValueError):self.g.retire_result(child,stdout_sha256=value,stderr_sha256=result.stderrSha256)
        self.assertTrue(child.stdout.exists());self.assertTrue(child.stderr.exists());self.assertEqual(len(self.policy.tokens),1)
    def test_sparse_oversize_log_is_rejected_before_stream_hash(self):
        child=self.g.run_node('inert');result=self.g.result(child)
        # Fake limits only: sparse metadata exercises pre-read size admission,
        # without allocating/writing33MiB or claiming native limit enforcement.
        with child.stdout.open('r+b') as stream:stream.truncate(33*1024**2)
        with self.assertRaises(ValueError):self.g.retire_result(child,stdout_sha256=result.stdoutSha256,stderr_sha256=result.stderrSha256)
        self.assertTrue(child.stdout.exists());self.assertEqual(len(self.policy.tokens),1)
    def test_fatal_or_custom_file_signal_rejected_before_limits_or_children(self):
        for index,disposition in enumerate((0,lambda *_:None)):
            work=self.root/('unsafe-file-signal-'+str(index));work.mkdir(mode=0o700);limits=Limits();signals=FileSignals(disposition)
            policy=r.ResourcePolicy(resource_api=limits,signal_api=signals);backend=core.Fake(self.clock)
            guardian=m.Guardian(work,self.tools,started=0,backend=backend,clock=self.clock,sleep=self.clock.sleep,signals=core.Signals(),log_policy=policy)
            backend.guardian=guardian
            with self.assertRaises(r.ResourceLimit):guardian.install()
            self.assertEqual(limits.events,[]);self.assertEqual(backend.children,[]);self.assertEqual(backend.events,[])
            result=guardian.finish_owner();self.assertTrue(result['completed']);self.assertFalse(result['qualificationEligible'])
if __name__=='__main__':unittest.main()
