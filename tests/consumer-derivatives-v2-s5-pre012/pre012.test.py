"""Pure source/fail-closed tests. No children, probes or SQL execution."""
from pathlib import Path
import ast
import copy
import hashlib
import importlib.util
import json
import unittest
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
h=load('pre012_harness',HERE/'s5.py')
# Admission precedes all other dynamic source imports.
h.dependencies()
m=load('pre012_cases_test',HERE/'cases.py')
p=load('pre012_pred_test',ROOT/'tests/consumer-derivatives-v2/predecessor-model.py')
contract=json.loads((ROOT/'staging/consumer-derivatives-v2/predecessor-contract.json').read_bytes())
cases=m.build(contract)
def synthetic():
    return [{'section':'selected','rows':copy.deepcopy(contract['constraints'])},
        {'section':'constraints','rows':[dict(catalog=dict(oid=i+100,conname=r['name']),relation='consumer_authorization',definition=r['definition']) for i,r in enumerate(contract['constraints'])]+[dict(catalog=dict(oid=999,conname='ordinary_fk'),relation='consumer_authorization',definition='ordinary')]},
        {'section':'triggers','rows':[dict(catalog=dict(oid=500+i,tgconstraint=100),definition='raw-internal-'+str(i)) for i in range(4)]+[dict(catalog=dict(oid=600,tgconstraint=999),definition='ordinary')]},
        {'section':'objects','rows':[dict(name='consumer_authorization',checks=4)]},
        {'section':'functions','rows':[dict(definition='approval raw bytes',owner='owner',acl=['unchanged'])]}]
class Pre012Tests(unittest.TestCase):
    def test_exact_ten_and_raw_operator_embedding(self):
        self.assertEqual(len(cases),10);self.assertEqual(len({c['id'] for c in cases}),10)
        op=(ROOT/'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql').read_text()
        for case in cases:
            sql=m.branch_sql(case,'SELECT 1;',op)
            self.assertEqual(sql.count(op),1);self.assertTrue(sql.startswith('BEGIN;\n'+case['setupSql']))
            self.assertLess(sql.index(case['id']+':SETUP_END'),sql.index(case['id']+':ATTEMPT'))
            self.assertLess(sql.index(case['id']+':ATTEMPT'),sql.index(op))
    def test_every_strict_field_remains_admitted_exactly(self):
        self.assertTrue(p.admit_predecessors(contract['constraints'],contract))
        for index,row in enumerate(contract['constraints']):
            for key in row:
                changed=copy.deepcopy(contract['constraints']);changed[index][key]='wrong-name' if key=='name' else (None if row[key] is not None else 'wrong')
                with self.subTest(name=row['name'],field=key),self.assertRaises(ValueError):p.admit_predecessors(changed,contract)
    def test_raw_changes_preserve_unselected_constraints_and_triggers(self):
        baseline=synthetic();saved=copy.deepcopy(baseline)
        for case in cases:
            expected=m.expected_setup(case,baseline,contract);s={r['section']:r['rows'] for r in expected}
            self.assertEqual(s['constraints'][-1],baseline[1]['rows'][-1]);self.assertEqual(s['triggers'][-1],baseline[2]['rows'][-1]);self.assertEqual(s['functions'],baseline[-1]['rows'])
            if case['mutation']=='renamed':
                self.assertEqual(s['triggers'],baseline[2]['rows']);self.assertEqual(s['objects'],baseline[3]['rows'])
            elif case['name']==contract['constraints'][0]['name']:self.assertEqual(len(s['triggers']),1)
            else:self.assertEqual(s['objects'][0]['checks'],3)
            with self.assertRaises(ValueError):p.admit_predecessors(s['selected'],contract)
        self.assertEqual(baseline,saved)
    def test_marker_and_error_fail_closed(self):
        case=cases[0];a,b,c,d=m.markers(case);stdout=a+'\n[]\n'+b+'\n'+c+'\n\n';stderr='WARNING:  25001: there is already a transaction in progress\nERROR:  55000: '+m.MESSAGE+'\n'
        self.assertEqual(m.parse_result(case,stdout,stderr,json.loads),[])
        for out,err in [(stdout+d+'\n',stderr),(stdout.replace(b+'\n',''),stderr),('noise\n'+stdout,stderr),(stdout+'noise\n',stderr),(stdout,stderr.replace('55000','P0001')),(stdout,stderr+'ERROR:  42601: syntax error\n')]:
            with self.assertRaises(ValueError):m.parse_result(case,out,err,json.loads)
    def test_exact_advisory_lock_empty_result_tail(self):
        case=cases[0];a,b,c,_=m.markers(case)
        prefix=a+'\n[]\n'+b+'\n'+c+'\n'
        stderr='ERROR:  55000: '+m.MESSAGE+'\n'
        self.assertEqual(m.parse_result(case,prefix+'\n',stderr,json.loads),[])
        for tail in ('','\n\n','unexpected\n',' \n','\nunexpected\n','unexpected\n\n'):
            with self.subTest(tail=repr(tail)),self.assertRaises(ValueError):
                m.parse_result(case,prefix+tail,stderr,json.loads)
    def test_prefix_is_explicit_and_stops_at_approval(self):
        tree=ast.parse((HERE/'prefix.py').read_text())
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='base' and n.func.attr=='execute' for n in ast.walk(tree)))
        src=(HERE/'prefix.py').read_text();self.assertIn("steps=[*base.baseline_steps_with_ledger(old,ledger),old[30]]",src)
        transcript=json.loads((ROOT/'artifacts/consumer-derivatives-v2-s0-s4/c98ddbfa-5495-4a40-851f-72ccd3361e92/reference-transcripts.json').read_bytes())
        self.assertEqual(transcript['referenceOld']['steps'][30]['id'],'candidate:approval-intent.candidate.sql')
        raw=(HERE/'raw-capture.sql').read_text();self.assertNotIn('::regclass',raw);self.assertNotIn('::regprocedure',raw)
        self.assertIn('pg_get_triggerdef',raw);self.assertIn('pg_get_functiondef',raw)
    def test_gate_needs_receipt_and_independent_outer_exit(self):
        manifest=dict(status='PROVISIONAL_PRE012_SUBSET_PENDING_ROOT_REVIEW',authoritative=False,cleanup={'completed':True},originalInputsUnchanged=True,stages={'PRE012_PREFIX':'PASS','PRE012_SUBSET':'SUBSET_PASS','S3':'NOT_RUN','S4':'NOT_RUN'},fullS5Qualified=False,boundedSubsetCompleted=True,qualification={'S5':False},pre012Completed=True,pre012Count=10,runId='run')
        raw=json.dumps(manifest).encode();receipt=dict(status='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO',manifestSha256=hashlib.sha256(raw).hexdigest(),runId='run',requiresOwnedControllerExitCode=0,originalOuterDeadlineSeconds=900)
        outer=dict(runId='run',ownedControllerExitCode=0,completed=True,originalOuterDeadlineSeconds=900,elapsedSeconds=899)
        self.assertTrue(h.completion_is_admissible(raw,receipt,outer))
        for key,value in [('ownedControllerExitCode',1),('completed',False),('elapsedSeconds',900),('runId','other')]:
            changed={**outer,key:value};self.assertFalse(h.completion_is_admissible(raw,receipt,changed))
        self.assertFalse(h.completion_is_admissible(raw,{},outer))
        manifest['stages']['S3']='PASS';self.assertFalse(h.completion_is_admissible(json.dumps(manifest).encode(),receipt,outer))
    def test_all_local_python_compiles(self):
        for f in HERE.glob('*.py'):compile(f.read_bytes(),str(f),'exec')
if __name__=='__main__':unittest.main()
