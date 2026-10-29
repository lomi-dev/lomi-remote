"""Pure structural/fail-closed tests using accepted independent raw templates."""
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
h=load('extended_harness_test',HERE/'s5.py');lock=h.dependencies()
m=load('extended_cases_test',HERE/'cases.py')
protocol=load('extended_protocol_test',ROOT/'tests/consumer-derivatives-v2-s5-pre012/cases.py')
predecessor=load('extended_pred_test',ROOT/'tests/consumer-derivatives-v2/predecessor-model.py')
contract=json.loads((ROOT/'staging/consumer-derivatives-v2/predecessor-contract.json').read_bytes())
reference=json.loads((ROOT/lock['referenceRawCapture']).read_bytes());cases=m.build(contract)
# This synthetic builtin identity fixture is not measured PG evidence.
builtin_oids={}
for row in m.sections(reference)['triggers']:
    for name in m.NAMES:
        if row['definition'].endswith('EXECUTE FUNCTION "'+name+'"()'):builtin_oids[name]=row['catalog']['tgfoid']
for index,name in enumerate(m.NAMES):builtin_oids.setdefault(name,str(800000+index))
builtin_rows=[dict(catalog=dict(oid=builtin_oids[name],proname=name,prosrc=name,prokind='f',pronargs=0,proargtypes=[],prosecdef=False,proretset=False),namespace='pg_catalog',language='internal',returnNamespace='pg_catalog',returnType='trigger') for name in m.NAMES]
def observed_ids(case):
    observed=copy.deepcopy(reference);s=m.sections(observed)
    if case['kind']=='reapply':return observed
    row=m.one(s['constraints'],lambda r:r['relation']=='consumer_authorization' and r['catalog']['conname']==case['name']);oldoid=row['catalog']['oid']
    if case['mutation']=='duplicate':row=copy.deepcopy(row);s['constraints'].append(row)
    row['catalog']['oid']='900000';row['catalog']['conname']=case['newName']
    if case['kind']=='fk':
        for index,t in enumerate(r for r in s['triggers'] if r['catalog']['tgconstraint']==oldoid):
            t['catalog']['oid']=str(900001+index);t['catalog']['tgconstraint']='900000'
    return observed
class ExtendedTests(unittest.TestCase):
    def test_case_closure_no_prior_missing_rename_or_ctas(self):
        self.assertEqual(len(cases),18);self.assertEqual(len({c['id'] for c in cases}),18)
        self.assertEqual(sum(c['kind']=='check' for c in cases),12);self.assertEqual(sum(c['kind']=='fk' for c in cases),5)
        self.assertEqual(cases[-1]['kind'],'reapply')
        self.assertFalse(any('CREATE TABLE' in c['setupSql'] or c['mutation'] in ('missing','renamed') for c in cases))
    def test_unchanged_protocol_and_whole012(self):
        op=(ROOT/'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql').read_text()
        for case in cases:
            sql=protocol.branch_sql(case,'SELECT raw;',op);self.assertEqual(sql.count(op),1)
            self.assertLess(sql.index(case['id']+':ATTEMPT'),sql.index(op))
            a,b,c,_=protocol.markers(case);stdout=a+'\n[]\n'+b+'\n'+c+'\n\n';stderr='ERROR:  55000: '+protocol.MESSAGE+'\n'
            self.assertEqual(protocol.parse_result(case,stdout,stderr,json.loads),[])
            with self.assertRaises(ValueError):protocol.parse_result(case,stdout+'\n',stderr,json.loads)
    def test_all_expected_structures_are_stable_and_preserve_unaffected_sections(self):
        saved=copy.deepcopy(reference)
        for case in cases:
            expected=m.expected_setup(case,reference,observed_ids(case),reference,builtin_oids)
            self.assertEqual(m.expected_setup(case,reference,expected,reference,builtin_oids),expected)
            before=m.sections(reference);after=m.sections(expected)
            for section in before.keys()-{'constraints','selected','triggers','objects'}:self.assertEqual(after[section],before[section])
            if case['kind']=='check':self.assertEqual(after['triggers'],before['triggers'])
            if case['mutation']!='duplicate':self.assertEqual(after['objects'],before['objects'])
            if case['kind']!='reapply':
                with self.assertRaises(ValueError):predecessor.admit_predecessors(after['selected'],contract)
        self.assertEqual(reference,saved)
    def test_independent_check_expression_fields_and_validation(self):
        for case in (c for c in cases if c['kind']=='check'):
            out=m.sections(m.expected_setup(case,reference,observed_ids(case),reference,builtin_oids))
            row=m.one(out['constraints'],lambda r:r['catalog']['conname']==case['newName'])
            independent=m.one(m.sections(reference)['constraints'],lambda r:r['catalog']['conname']==case['expressionSource'])
            self.assertEqual(row['catalog']['conbin'],independent['catalog']['conbin']);self.assertEqual(row['catalog']['conkey'],independent['catalog']['conkey'])
            self.assertEqual(row['catalog']['convalidated'],case['mutation']!='notvalid')
            self.assertEqual(out['objects'][[r['name'] for r in out['objects']].index('consumer_authorization')]['checks'],m.one(m.sections(reference)['objects'],lambda r:r['name']=='consumer_authorization')['checks']+(case['mutation']=='duplicate'))
    def test_no_other_raw_field_can_self_bless(self):
        for case in cases[:-1]:
            expected=m.expected_setup(case,reference,observed_ids(case),reference,builtin_oids)
            for section,key in [('constraints','definition'),('triggers','definition'),('objects','relowner')]:
                hostile=copy.deepcopy(expected);rows=m.sections(hostile)[section];rows[-1][key]='unexpected'
                self.assertNotEqual(hostile,m.expected_setup(case,reference,hostile,reference,builtin_oids))
    def test_fresh_oid_and_closed_fk_trigger_cardinality(self):
        case=next(c for c in cases if c['kind']=='fk');out=m.expected_setup(case,reference,observed_ids(case),reference,builtin_oids)
        for invalid in ('0','-1','01',1,m.sections(reference)['constraints'][0]['catalog']['oid'],m.sections(reference)['objects'][0]['oid'],builtin_oids[m.NAMES[0]]):
            hostile=copy.deepcopy(out);r=m.one(m.sections(hostile)['constraints'],lambda r:r['catalog']['conname']==m.FK);r['catalog']['oid']=invalid
            with self.assertRaises(ValueError):m.expected_setup(case,reference,hostile,reference,builtin_oids)
        for mode in ('missing','duplicate','reuse-constraint-oid'):
            hostile=copy.deepcopy(out);s=m.sections(hostile);rows=[r for r in s['triggers'] if r['catalog']['tgconstraint']=='900000']
            if mode=='missing':s['triggers'].remove(rows[0])
            elif mode=='duplicate':s['triggers'].append(copy.deepcopy(rows[0]))
            else:rows[0]['catalog']['oid']='900000'
            with self.assertRaises(ValueError):m.expected_setup(case,reference,hostile,reference,builtin_oids)
    def test_fk_trigger_actions_and_deferral(self):
        immediate=next(c for c in cases if c['id']=='fk-immediate')
        self.assertTrue(immediate['definition'].endswith(' DEFERRABLE'));self.assertIn(' DEFERRABLE INITIALLY IMMEDIATE;',immediate['setupSql'])
        for case in (c for c in cases if c['kind']=='fk'):
            s=m.sections(m.expected_setup(case,reference,observed_ids(case),reference,builtin_oids));rows=[r for r in s['triggers'] if r['catalog']['tgconstraint']=='900000'];self.assertEqual(len(rows),4)
            for row in rows:
                raw=row['catalog'];name=next(n for n in m.NAMES if builtin_oids[n]==raw['tgfoid'])
                expected_defer=case['mutation'] in ('immediate','deferred') and name not in ('RI_FKey_cascade_del','RI_FKey_restrict_del','RI_FKey_cascade_upd')
                self.assertEqual(raw['tgdeferrable'],expected_defer);self.assertEqual(raw['tginitdeferred'],expected_defer and case['mutation']=='deferred')
                self.assertIn(raw['tgname'],row['definition']);self.assertTrue(row['definition'].endswith('EXECUTE FUNCTION "'+name+'"()'))
            functions={r['catalog']['tgfoid'] for r in rows}
            self.assertIn(builtin_oids['RI_FKey_restrict_del' if case['mutation']=='delete-restrict' else 'RI_FKey_cascade_del'],functions)
            self.assertIn(builtin_oids['RI_FKey_cascade_upd' if case['mutation']=='update-cascade' else 'RI_FKey_noaction_upd'],functions)
    def test_builtin_capture_fails_closed(self):
        self.assertEqual(m.admit_builtins(builtin_rows,reference),builtin_oids)
        for key,value in [('namespace','public'),('language','sql'),('returnType','text'),('returnNamespace','public')]:
            hostile=copy.deepcopy(builtin_rows);hostile[0][key]=value
            with self.assertRaises(ValueError):m.admit_builtins(hostile,reference)
        for key,value in [('oid','0'),('oid','880000'),('prosrc','wrong'),('prokind','p'),('pronargs',1),('proargtypes','23'),('proargtypes',''),('proargtypes',None),('proargtypes',[23]),('proargtypes',['23']),('proargtypes',False),('proargtypes',{}),('prosecdef',True),('proretset',True)]:
            hostile=copy.deepcopy(builtin_rows);hostile[0]['catalog'][key]=value
            with self.assertRaises(ValueError):m.admit_builtins(hostile,reference)
        with self.assertRaises(ValueError):m.admit_builtins(builtin_rows[:-1],reference)
        with self.assertRaises(ValueError):m.admit_builtins([builtin_rows[0]]*6,reference)
    def test_first012_commit_marker_and_second_baseline_are_separate(self):
        op=(ROOT/'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql').read_text();script=m.first012_script(op)
        self.assertTrue(script.startswith(op));self.assertEqual(script.count(op),1)
        self.assertGreater(script.index("SELECT 'FIRST012_COMMITTED'"),script.rindex('COMMIT;'))
        self.assertTrue(m.admit_first012_stdout('\nFIRST012_COMMITTED\n'))
        for text in ('','FIRST012_COMMITTED\n','\nFIRST012_COMMITTED\n\n','\nUNEXPECTED_ACCEPTANCE\n'):
            with self.assertRaises(ValueError):m.admit_first012_stdout(text)
        src=(HERE/'s5.py').read_text();self.assertIn('base.require(index==17 and len(results)==17',src)
        self.assertLess(src.index('output=f.sql(database'),src.index('baseline[database]=postfirst'))
        self.assertLess(src.index('baseline[database]=postfirst'),src.index('script=protocol.branch_sql'))
        self.assertIn("if db!=migrated:predecessor.admit_predecessors",src)
    def test_reapply_setup_must_equal_postfirst_baseline(self):
        post=copy.deepcopy(reference);m.sections(post)['objects'][0]['name']='post-first-fixture'
        self.assertEqual(m.expected_setup(cases[-1],post,post,reference,builtin_oids),post)
        hostile=copy.deepcopy(post);m.sections(hostile)['objects'][0]['name']='unexpected'
        self.assertNotEqual(m.expected_setup(cases[-1],post,hostile,reference,builtin_oids),hostile)
    def test_completion_gate_no_overpromotion(self):
        manifest=dict(status='PROVISIONAL_PRE012_EXTENDED_SUBSET_PENDING_ROOT_REVIEW',authoritative=False,cleanup={'completed':True},originalInputsUnchanged=True,stages={'PRE012_PREFIX':'PASS','PRE012_EXTENDED_SUBSET':'SUBSET_PASS','S3':'NOT_RUN','S4':'NOT_RUN'},fullS5Qualified=False,boundedSubsetCompleted=True,qualification={'S5':False},extendedCompleted=True,extendedCount=18,first012Committed=True,priorAccepted10ChecksReexecuted=False,remainingConstructibleCases=4,runId='run')
        def check(value,outer_change=None):
            raw=json.dumps(value).encode();receipt=dict(status='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO',manifestSha256=hashlib.sha256(raw).hexdigest(),runId='run',requiresOwnedControllerExitCode=0,originalOuterDeadlineSeconds=900);outer=dict(runId='run',ownedControllerExitCode=0,completed=True,originalOuterDeadlineSeconds=900,elapsedSeconds=20);outer.update(outer_change or {});return h.completion_is_admissible(raw,receipt,outer)
        self.assertTrue(check(manifest))
        for key,value in [('extendedCount',17),('first012Committed',False),('priorAccepted10ChecksReexecuted',True),('remainingConstructibleCases',0),('fullS5Qualified',True)]:self.assertFalse(check({**manifest,key:value}))
        for key,value in [('ownedControllerExitCode',1),('elapsedSeconds',900),('completed',False)]:self.assertFalse(check(manifest,{key:value}))
    def test_python_compile_and_pinned_prior_capture(self):
        for f in HERE.glob('*.py'):compile(f.read_bytes(),str(f),'exec')
        self.assertEqual(hashlib.sha256((ROOT/'tests/consumer-derivatives-v2-s5-pre012/raw-capture.sql').read_bytes()).hexdigest(),'f02407bb59dc4bf5237e3252359978bc1d5708fa6a25ee258c88c7ff66dcd868')
        ast.parse((HERE/'s5.py').read_text())
if __name__=='__main__':unittest.main()
