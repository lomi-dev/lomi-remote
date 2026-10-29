"""Pure source/phase/delta/gate tests only; no child invocation on import."""
from pathlib import Path
import ast
import copy
import hashlib
import importlib.util
import json
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import tempfile
import shutil
import contextlib
import io

HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

h=load('admission_harness',HERE/'s5.py');m=load('admission_model',HERE/'admission.py')

class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _,cls.c,cls.a,cls.base,cls.compare=h.authorities();cls.expected=cls.a[3]['old'];cls.compare=staticmethod(cls.compare)

    def synthetic(self,case):
        data=copy.deepcopy(self.expected);cat=data['catalog'];meta=data['metadata']
        if case['unknown']:
            role=dict(kind='role',name=m.UNKNOWN,login=False,inherit=False,super=False,createRole=False,createDb=False,replication=False,bypassRls=False,config=None)
            cat.append(copy.deepcopy(role));meta.append(role);meta.append(dict(kind='schemaAuthority',role=m.UNKNOWN,create=False,usage=True))
        grantee=m.UNKNOWN if case['unknown'] else ('lomi_migrator' if case['default'] else 'lomi_remote_api')
        if case['default']:
            default=dict(kind='defaultAcl',owner='e2_owner',namespace='public',objectType='r',grantor='e2_owner',grantee=grantee,privilege='SELECT',grantable=False)
            meta.append(default);cat.append(dict(default,namespace='2200'))
            for name in m.NEW_TABLES:meta.append(dict(kind='objectAcl',relation=name,owner='e2_owner',grantor='e2_owner',grantee=grantee,privilege='SELECT',grantable=False))
            for row in cat:
                if row.get('kind')=='protectedAcl' and row['relation'] in m.NEW_TABLES:row['tableAcl'].insert(1,grantee+'=r/e2_owner')
        if case['column']:
            meta.append(dict(kind='columnAcl',relation='consumer_authorization',column='originId',grantor='e2_owner',grantee=grantee,privilege='UPDATE',grantable=False))
            row=next(r for r in cat if r.get('kind')=='protectedAcl' and r['relation']=='consumer_authorization' and r['column']=='originId');row['columnAcl'].append(grantee+'=w/e2_owner')
        # Synthetic fixtures use the pinned discovery SELECT group order, so
        # original-order diagnostic masking differs from targeted phase results.
        cat.sort(key=lambda r:['function','role','membership','defaultAcl','protectedAcl','assertionTypeAcl'].index(r['kind']))
        order=['objectAcl','columnAcl','schemaAuthority','constraint','trigger','index','role','membership','defaultAcl','relationIdentity']
        meta.sort(key=lambda r:order.index(r['kind']))
        return data

    def test_exact_five_categories_and_before_after_sql(self):
        self.assertEqual(len(m.CASES),5);self.assertEqual(len({c['id'] for c in m.CASES}),5)
        for case in m.CASES:
            before=m.setup_before(case);after=m.setup_after(case)
            if case['default']:
                self.assertIn('FOR ROLE e2_owner IN SCHEMA public GRANT SELECT ON TABLES',before)
                self.assertNotIn('FOR ROLE lomi_migrator',before)
            if case['column']:self.assertIn('UPDATE("originId")',after)
            self.assertNotIn('REVOKE',before+after)

    def test_five_admission_phases_no_masking_and_no_mutation(self):
        for case in m.CASES:
            data=self.synthetic(case);before=copy.deepcopy(data)
            rawcat=(json.dumps(data['catalog'],indent=2)+'\n').encode();rawmeta=(json.dumps(data['metadata'],indent=2)+'\n').encode()
            r=m.classify(self.base,self.compare,rawcat,rawmeta,self.expected,case)
            self.assertEqual(r['category'],case['category']);self.assertEqual(r['message'],case['message']);self.assertEqual(data,before)
            for phase in r['phaseEvidence']:
                self.assertEqual(phase['fullCaptureSha256'],hashlib.sha256(rawmeta).hexdigest())
                self.assertEqual(phase['indices'],m.phase_indices(data['metadata'],phase['phase']))
            self.assertFalse(r['pinsAccepted']);self.assertFalse(r['derivationAttempted']);self.assertIsNone(r['sqlstate'])
            if case['unknown']:
                self.assertEqual(r['fullOriginalOrderGuard']['catalog']['message'],'unknown fixture role')
                self.assertEqual(r['fullOriginalOrderGuard']['metadata']['message'],'unknown object privilege' if case['default'] or case['column'] else 'unknown fixture role')
            else:
                self.assertTrue(all(x['passed'] for x in r['fullOriginalOrderGuard'].values()))
                self.assertEqual(r['referenceComparison']['message'],'metadata differs from admitted independent reference')

    def test_exact_declared_delta_only(self):
        for case in m.CASES:
            data=self.synthetic(case);qualified=dict(case,publicNamespaceOid='2200')
            m.validate_declared_delta(self.base,self.compare,data['catalog'],data['metadata'],self.expected,qualified)
            bad=copy.deepcopy(data);next(r for r in bad['catalog'] if r['kind']=='function')['owner']='fixture_unexpected'
            with self.assertRaises(ValueError):m.validate_declared_delta(self.base,self.compare,bad['catalog'],bad['metadata'],self.expected,qualified)

    def test_namespace_oid_string_is_pristine_and_strict(self):
        raw=[{'section':'schemas','rows':[{'catalog':{'oid':'2200','nspname':'public'}}]}]
        before=copy.deepcopy(raw)
        self.assertEqual(m.pristine_public_namespace_oid(raw),'2200');self.assertEqual(raw,before)
        case=next(c for c in m.CASES if c['id']=='known-default');data=self.synthetic(case)
        for bad in (2200,True,None,b'2200','','0','02200','+2200','2200 ',' 2200','٢٢٠٠','2200.0'):
            with self.assertRaises(ValueError):m.canonical_oid(bad)
            changed=copy.deepcopy(raw);changed[0]['rows'][0]['catalog']['oid']=bad
            with self.assertRaises(ValueError):m.pristine_public_namespace_oid(changed)
            with self.assertRaises(ValueError):m.validate_declared_delta(self.base,self.compare,data['catalog'],data['metadata'],self.expected,dict(case,publicNamespaceOid=bad))
        with self.assertRaises(ValueError):m.pristine_public_namespace_oid(raw+copy.deepcopy(raw))
        changed=copy.deepcopy(raw);changed[0]['rows'][0]['catalog']['nspname']='other'
        with self.assertRaises(ValueError):m.pristine_public_namespace_oid(changed)

    def test_missing_propagation_or_extra_grant_rejects(self):
        case=next(c for c in m.CASES if c['id']=='unknown-default');data=self.synthetic(case)
        bad=copy.deepcopy(data);bad['metadata']=[r for r in bad['metadata'] if not (r.get('kind')=='objectAcl' and r['relation']=='consumer_derivative_consent' and r['grantee']==m.UNKNOWN)]
        with self.assertRaises(ValueError):m.validate_declared_delta(self.base,self.compare,bad['catalog'],bad['metadata'],self.expected,dict(case,publicNamespaceOid='2200'))
        case=next(c for c in m.CASES if c['id']=='known-column');data=self.synthetic(case)
        data['metadata'].append(dict(kind='columnAcl',relation='consumer_authorization',column='originId',grantor='e2_owner',grantee='PUBLIC',privilege='UPDATE',grantable=False))
        with self.assertRaises(ValueError):m.validate_declared_delta(self.base,self.compare,data['catalog'],data['metadata'],self.expected,case)

    def test_wrong_phase_and_pristine_acceptance_do_not_pass(self):
        case=m.CASES[0];data=self.synthetic(case)
        with self.assertRaises(ValueError):m.classify(self.base,self.compare,json.dumps(data['catalog']).encode(),json.dumps(data['metadata']).encode(),self.expected,dict(case,phase='DEFAULT_ACL'))
        with self.assertRaises(ValueError):m.classify(self.base,self.compare,json.dumps(self.expected['catalog']).encode(),json.dumps(self.expected['metadata']).encode(),self.expected,case)

    def test_baseline_only_exact_scaffold_delta_and_raw_copy(self):
        old=h.ROOT/'artifacts/consumer-derivatives-v2-s5-pre012-preparation/548c7da2-e8b9-4dfa-8e53-fd693f40ab37/qualification-source'
        text=(old/'prefix.py').read_text().replace('Explicit prefix runner. Never calls the full S0-S4 execute function.','Explicit baseline-only runner, stopping BEFORE old[30] candidate creation.')
        text=text.replace('steps=[*base.baseline_steps_with_ledger(old,ledger),old[30]]','steps=base.baseline_steps_with_ledger(old,ledger)')
        text=text.replace("'pre012-prefix-schedule.json',dict(steps=steps,prismaLedgerQualified=False,stoppedBefore012=True)","'baseline-only-schedule.json',dict(steps=steps,prismaLedgerQualified=False,stoppedBeforeOld30=True)")
        text=text.replace("return dict(status='PREFIX_CONSTRUCTED',stages={'PRE012_PREFIX':'PASS','S3':'NOT_RUN','S4':'NOT_RUN'},qualification={'S5':False})",'return built')
        self.assertEqual((HERE/'baseline.py').read_text(),text);self.assertTrue((HERE/'raw-capture.sql').read_bytes().startswith((old/'raw-capture.sql').read_bytes()))
        predecessor=load('admission_raw_projection',h.ROOT/'tests/consumer-derivatives-v2/predecessor-model.py');contract=json.loads((h.ROOT/'staging/consumer-derivatives-v2/predecessor-contract.json').read_bytes());guard=predecessor.guard_sql(contract);projection=guard[guard.index(' SELECT coalesce('):guard.index(' IF actual IS DISTINCT')].replace(' INTO actual','',1)
        self.assertEqual((HERE/'raw-capture.sql').read_text(),(old/'raw-capture.sql').read_text()+"SELECT jsonb_build_object('section','selected','rows',q.value) FROM ("+projection.strip().removesuffix(';')+") q(value);\n")
        self.assertEqual((HERE/'raw-capture.sql').read_text().count("SELECT jsonb_build_object('section'"),27)

    def test_no_pin_constructor_or_operator_entrypoint(self):
        tree=ast.parse((HERE/'s5.py').read_bytes())
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='construct' for n in ast.walk(tree)))
        self.assertNotIn("'--derived'",(HERE/'s5.py').read_text());self.assertNotIn('operator-three-roots.candidate.sql',(HERE/'s5.py').read_text())

    def test_injected_case_evidence_failure_still_stops_owned_cluster(self):
        calls=[];works=[]
        class FakeFixture:
            def __init__(self,owned,lock,work,evidence,appointment,node):
                self.work=work;self.evidence=evidence;self.evidence_errors=[];works.append(work)
            def cleanup(self):
                calls.append('owned-stop/status');return dict(completed=True,pgCtlStatus=3,postmasterPidAbsent=True,socketDirectoryEmpty=True)
            def try_save(self,name,value):calls.append('cleanup-evidence')
        def require(ok,message):
            if not ok:raise ValueError(message)
        fake=SimpleNamespace(Fixture=FakeFixture,NODE_HASH='fixed',checked=lambda *a:b'fixed',
            require=require,remaining_budget=lambda *a:900,toolchain=lambda *a:{'tool':'fixed'},
            admit_sources=lambda:({}, {}, {'tool':'fixed'},None))
        owned=SimpleNamespace(initialize_process_ownership=lambda:None)
        def loader(name,path):
            return owned if name=='admission_owned' else SimpleNamespace(CASES=m.CASES)
        with tempfile.TemporaryDirectory() as dest:
            try:
                with patch.object(h,'ROOT',Path(dest)),patch.object(h,'authorities',lambda:({},None,None,fake,None)),patch.object(h,'closure',lambda:{}),patch.object(h,'load',loader),patch.object(h,'run_case',side_effect=OSError('injected normal evidence write failure')),patch.object(h.signal,'signal'),patch.object(h.signal,'setitimer'),patch.object(h.resource,'setrlimit'),patch.object(h.shutil,'disk_usage',return_value=SimpleNamespace(free=3*1024**3)),patch.object(h.sys,'argv',['s5.py','--appointment','pure-test','--node','/usr/bin/true']),contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as exit_:h.main()
                self.assertEqual(exit_.exception.code,1)
                self.assertEqual(calls,['owned-stop/status','cleanup-evidence'])
            finally:
                for work in works:
                    if work.exists():shutil.rmtree(work)

    def test_completion_fails_closed_on_promotion_pins_cleanup_deadline(self):
        manifest=dict(status='PROVISIONAL_ADMISSION_SUBSET_PENDING_ROOT_REVIEW',authoritative=False,fullS5Qualified=False,boundedSubsetCompleted=True,admissionFaultsCompleted=True,admissionFaultCount=5,
            stages={'ADMISSION_SUBSET':'SUBSET_PASS','S5':'SUBSET_PASS'},pinsAccepted=False,derivationAttempted=False,measuredOperatorsExecuted=False,qualification={'S5':False},cleanup={'completed':True,'privateDirectoriesAbsent':True},originalInputsUnchanged=True,evidenceWriteErrors=[],runId='t')
        ctl=dict(runId='t',completed=True,ownedControllerExitCode=0,originalOuterDeadlineSeconds=900,elapsedSeconds=2)
        def gate(m,ctl=ctl):
            raw=json.dumps(m).encode();receipt=dict(status='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO',manifestSha256=hashlib.sha256(raw).hexdigest(),runId='t',requiresOwnedControllerExitCode=0,originalOuterDeadlineSeconds=900);return h.completion_is_admissible(raw,receipt,ctl)
        self.assertTrue(gate(manifest))
        for change in (lambda m:m.update(fullS5Qualified=True),lambda m:m.update(pinsAccepted=True),lambda m:m.update(derivationAttempted=True),lambda m:m.update(admissionFaultCount=4),lambda m:m['cleanup'].update(privateDirectoriesAbsent=False),lambda m:m['stages'].update(S5='PASS')):
            bad=copy.deepcopy(manifest);change(bad);self.assertFalse(gate(bad))
        self.assertFalse(gate(manifest,{}));self.assertFalse(gate(manifest,{**ctl,'elapsedSeconds':900}))

if __name__=='__main__':unittest.main()
