"""Pure closed-source CTAS expectations; synthetic outputs are not PG evidence."""
from pathlib import Path
import ast
import copy
import hashlib
import importlib.util
import json
import sys
import unittest
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
DENIED=[]
def audit(event,args):
    if event in ('subprocess.Popen','os.fork','os.posix_spawn','os.system','os.kill','os.killpg','ctypes.dlopen'):
        DENIED.append(event);raise AssertionError('native/process event forbidden in CTAS pure tests')
sys.addaudithook(audit)
lock=json.loads((HERE/'inputs.lock.json').read_bytes())
for name,pin in {**lock['dependenciesSha256'],**{'tests/consumer-derivatives-v2-s5-pre012-ctas/'+n:p for n,p in lock['localSha256'].items()}}.items():
    path=ROOT/name
    if any(p.is_symlink() for p in (path,*path.parents)) or hashlib.sha256(path.read_bytes()).hexdigest()!=pin:raise AssertionError('admit before dynamic imports')
spec=importlib.util.spec_from_file_location('ctas_protocol',HERE/'protocol.py');p=importlib.util.module_from_spec(spec);sys.modules[spec.name]=p;spec.loader.exec_module(p)
MODULES=p.load_modules();m=MODULES['model']
BASELINE=json.loads((ROOT/lock['referenceRawCapture']).read_bytes())
BUILTIN_ROWS=json.loads((ROOT/lock['referenceBuiltinCapture']).read_bytes())
BUILTINS=MODULES['extended'].admit_builtins(BUILTIN_ROWS,BASELINE)
CASES=m.build()
IDS=dict(zip(m.OID_KEYS,map(str,(700000013,700000007,700000019,700000001,700000023,700000003,700000031,700000011,700000029,700000017)),strict=True))
EXPECTED=[m.expected_setup(case,BASELINE,IDS,BUILTINS) for case in CASES]

class CTAS(unittest.TestCase):
    def observed(self,index=0):return copy.deepcopy(EXPECTED[index])
    def reject(self,observed,index=0):
        with self.assertRaises((ValueError,KeyError,TypeError)):m.verify_setup(CASES[index],BASELINE,observed,BUILTINS)
    def metadata(self):
        return [dict(kind='objectAcl',grantor='e2_owner',grantee='e2_owner'),dict(kind='columnAcl',grantor='e2_owner',grantee='PUBLIC'),dict(kind='schemaAuthority',role='lomi_runtime',create=False),dict(kind='constraint'),dict(kind='trigger'),dict(kind='index'),dict(kind='role',name='e2_owner',**MODULES['base'].expected_role('e2_owner')),dict(kind='membership',role='pg_a',member='pg_b'),dict(kind='defaultAcl',owner='lomi_migrator',grantor='lomi_migrator',grantee='lomi_runtime'),dict(kind='relationIdentity')]
    def output(self,index=0,metadata=None):
        marks=p.markers(CASES[index]);raw=[json.dumps(row) for row in EXPECTED[index]];meta=[json.dumps(row) for row in (self.metadata() if metadata is None else metadata)]
        return '\n'.join([marks[0],*raw,marks[1],marks[2],*meta,marks[3],marks[4],''])+'\n'
    def stderr(self):return 'psql:fixture: WARNING: there is already a transaction in progress\npsql:fixture: ERROR:  55000: '+p.MESSAGE+'\n'
    def test_01_four_legal_recipes(self):
        self.assertEqual(len(CASES),4)
        for case in CASES:
            self.assertIn('WITH NO DATA',case['setupSql']);self.assertIn('ADD CONSTRAINT '+m.KEY+' UNIQUE',case['setupSql']);self.assertIn('ON DELETE CASCADE',case['setupSql']);self.assertIn('IF EXISTS (SELECT 1 FROM public.consumer_authorization)',case['setupSql']);self.assertNotIn('pg_catalog',case['setupSql'])
    def test_02_exact_synthetic_full_rows_bind_only10(self):
        for i,case in enumerate(CASES):
            result=m.verify_setup(case,BASELINE,EXPECTED[i],BUILTINS);self.assertEqual(result['identities'],IDS);self.assertFalse(result['fullS5Qualified'])
    def test_03_cardinalities(self):
        baseline=m.sections(BASELINE)
        for case,expected in zip(CASES,EXPECTED,strict=True):
            s=m.sections(expected);deltas=dict(objects=2,columns=2*len(case['targetColumns']),constraints=1 if case['replace'] else 2,indexes=1,triggers=0 if case['replace'] else 4,types=2,expandedRelationAcl=16,expandedTypeAcl=4,selected=0 if case['replace'] else 1)
            for name,rows in s.items():self.assertEqual(len(rows)-len(baseline[name]),deltas.get(name,0),(case['id'],name))
    def test_04_all_other_sections_exact(self):
        changed={'objects','columns','constraints','indexes','triggers','types','expandedRelationAcl','expandedTypeAcl','selected'}
        for expected in EXPECTED:
            for name,rows in m.sections(expected).items():
                if name not in changed:self.assertEqual(rows,m.sections(BASELINE)[name],name)
    def test_05_ctas_columns_reset_and_types(self):
        for case,expected in zip(CASES,EXPECTED,strict=True):
            columns=[r['catalog'] for r in m.sections(expected)['columns'] if r['catalog']['attrelid'] in (IDS['heap'],IDS['index'])]
            self.assertEqual(len(columns),2*len(case['targetColumns']))
            for raw in columns:
                for field,value in dict(attnotnull=False,atthasdef=False,attidentity='',attgenerated='',attacl=None,atthasmissing=False).items():self.assertEqual(raw[field],value)
    def test_06_selected_contract_rejects_all_four(self):
        MODULES['predecessor'].admit_predecessors(m.sections(BASELINE)['selected'],p.contract())
        for expected in EXPECTED:
            with self.assertRaisesRegex(ValueError,p.MESSAGE):MODULES['predecessor'].admit_predecessors(m.sections(expected)['selected'],p.contract())
    def test_07_no_oid_allocation_order_assumption(self):
        values=dict(zip(m.OID_KEYS,reversed(list(IDS.values())),strict=True))
        for case in CASES:self.assertEqual(m.verify_setup(case,BASELINE,m.expected_setup(case,BASELINE,values,BUILTINS),BUILTINS)['identities'],values)
    def test_08_oid_wrong_types_freshness_aliases(self):
        for value in ('0','01','-1','١','4294967296',1,None,IDS['index'],m.sections(BASELINE)['objects'][0]['oid'],BUILTINS['RI_FKey_check_ins']):
            values=dict(IDS,heap=value)
            with self.subTest(value=value),self.assertRaises(ValueError):m.expected_setup(CASES[0],BASELINE,values,BUILTINS)
        with self.assertRaises(ValueError):m.expected_setup(CASES[0],BASELINE,dict(IDS,extra='700001000'),BUILTINS)
    def test_09_heap_index_object_field_families(self):
        for identity in ('heap','index'):
            for field in ('relowner','relnamespace','relkind','reltype','checks','relhastriggers','relrowsecurity','relforcerowsecurity','relacl','reloptions','relpartbound'):
                observed=self.observed();row=m.one(m.sections(observed)['objects'],lambda r:r['oid']==IDS[identity]);row[field]=['WRONG'];self.reject(observed)
    def test_10_type_field_families(self):
        for identity in ('array','composite'):
            for field in ('typelem','typrelid','typarray','typname','typowner','typnamespace','typacl','typinput','typreceive','typcategory'):
                observed=self.observed();row=m.one(m.sections(observed)['types'],lambda r:r['catalog']['oid']==IDS[identity]);row['catalog'][field]=['WRONG'];self.reject(observed)
    def test_11_attribute_field_families(self):
        for field in ('attnotnull','attacl','atttypid','atttypmod','attcollation','attnum','attidentity','attgenerated','attstorage','attlen','attalign','attcompression','atthasdef','attmissingval'):
            observed=self.observed();row=m.one(m.sections(observed)['columns'],lambda r:r['catalog']['attrelid']==IDS['heap']);row['catalog'][field]=['WRONG'];self.reject(observed)
    def test_12_index_full_fields_and_arrays(self):
        for field in m.sections(EXPECTED[0])['indexes'][-1]['catalog']:
            observed=self.observed();row=m.one(m.sections(observed)['indexes'],lambda r:r['catalog']['indexrelid']==IDS['index']);row['catalog'][field]=['WRONG'];self.reject(observed)
    def test_13_constraint_full_fields(self):
        for identity in ('unique','fk'):
            template=m.one(m.sections(EXPECTED[0])['constraints'],lambda r:r['catalog']['oid']==IDS[identity])
            for field in template['catalog']:
                observed=self.observed();row=m.one(m.sections(observed)['constraints'],lambda r:r['catalog']['oid']==IDS[identity]);row['catalog'][field]=['WRONG'];self.reject(observed)
    def test_14_trigger_all_field_families_and_definition(self):
        for field in ('tgfoid','tgrelid','tgconstrrelid','tgconstraint','tgconstrindid','tgtype','tgdeferrable','tginitdeferred','tgenabled','tgisinternal','tgname','tgargs'):
            observed=self.observed();row=m.one(m.sections(observed)['triggers'],lambda r:r['catalog']['oid']==IDS['action_delete']);row['catalog'][field]=['WRONG'];self.reject(observed)
        observed=self.observed();m.one(m.sections(observed)['triggers'],lambda r:r['catalog']['oid']==IDS['check_update'])['definition']+=' ';self.reject(observed)
    def test_15_acl_every_row_exact(self):
        for section,identity in [('expandedRelationAcl','heap'),('expandedRelationAcl','index'),('expandedTypeAcl','array'),('expandedTypeAcl','composite')]:
            for field in ('grantor','grantee','privilege_type','is_grantable'):
                observed=self.observed();row=next(r for r in m.sections(observed)[section] if r['oid']==IDS[identity]);row[field]='WRONG';self.reject(observed)
    def test_16_extra_missing_reordered_rows(self):
        for section in ('objects','columns','constraints','indexes','triggers','types','expandedRelationAcl','expandedTypeAcl','selected'):
            for mutation in ('extra','missing','reorder'):
                observed=self.observed();rows=m.sections(observed)[section]
                if mutation=='extra':rows.append(copy.deepcopy(rows[-1]))
                elif mutation=='missing':rows.pop()
                else:rows.reverse()
                self.reject(observed)
    def test_17_unchanged_family_drift(self):
        for section in set(m.SECTIONS)-{'objects','columns','constraints','indexes','triggers','types','expandedRelationAcl','expandedTypeAcl','selected'}:
            observed=self.observed();m.sections(observed)[section].append({'undeclared':'drift'});self.reject(observed)
    def test_18_replacement_only_original_fk_and_four_removed(self):
        before=m.sections(BASELINE);after=m.sections(EXPECTED[3]);old=m.one(before['constraints'],lambda r:r['catalog']['conname']==m.FK and r['relation']==m.TABLE)['catalog']['oid']
        self.assertFalse(any(r['catalog']['oid']==old for r in after['constraints']));self.assertFalse(any(r['catalog']['tgconstraint']==old for r in after['triggers']))
        for row in before['constraints']:
            if row['catalog']['oid']!=old:self.assertIn(row,after['constraints'])
    def test_19_operator_bytes_and_real_metadata_query_inside(self):
        for case in CASES:
            sql=p.branch_sql(case,MODULES);operator=(ROOT/'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql').read_text();metadata=(ROOT/'tests/consumer-derivatives-v2/pg-s0-s4-metadata.sql').read_text()
            self.assertEqual(sql.count(operator),1);self.assertEqual(sql.count(metadata),1);self.assertLess(sql.index(metadata),sql.index(operator));self.assertTrue(sql.startswith('BEGIN;\n'))
    def test_20_protocol_exact_output_and_original_guard(self):
        result=p.verify_attempt(CASES[0],BASELINE,self.output(),self.stderr(),3,BUILTIN_ROWS,MODULES)
        self.assertEqual(result['authorityGuard']['marker'],CASES[0]['id']+':ORIGINAL_AUTHORITY_GUARD_RETURNED');self.assertFalse(result['authorityGuard']['rawEnvelopeShortcutUsed']);self.assertIn('ACTUAL_EXECUTION_NOT_ESTABLISHED',result['status'])
    def test_21_reject_vacuous_authority_envelopes_and_unknown_principal(self):
        with self.assertRaises(ValueError):p.parse_result(CASES[0],self.output(metadata=BASELINE),self.stderr(),3)
        metadata=self.metadata();metadata[0]['grantee']='unrecognized_principal'
        with self.assertRaises(Exception):p.verify_attempt(CASES[0],BASELINE,self.output(metadata=metadata),self.stderr(),3,BUILTIN_ROWS,MODULES)
    def test_22_marker_error_and_blank_tail_negatives(self):
        stdout=self.output();marks=p.markers(CASES[0])
        for output,error,code in [(stdout.rstrip()+'\n',self.stderr(),3),(stdout+'\n',self.stderr(),3),(stdout+'bad\n',self.stderr(),3),(stdout.replace(marks[4],marks[4]+'\n'+marks[4]),self.stderr(),3),(stdout+marks[5]+'\n',self.stderr(),3),(stdout,self.stderr().replace('55000','P0001'),3),(stdout,self.stderr(),0)]:
            with self.assertRaises(ValueError):p.parse_result(CASES[0],output,error,code)
    def test_23_all_three_raw_rollback_required(self):
        baseline={name:BASELINE for name in p.DATABASES};p.verify_rollback_all(baseline,baseline,MODULES)
        bad=dict(baseline);bad[p.DATABASES[1]]=EXPECTED[0]
        with self.assertRaises(ValueError):p.verify_rollback_all(baseline,bad,MODULES)
        with self.assertRaises(ValueError):p.verify_rollback_all(baseline,{p.DATABASES[0]:BASELINE},MODULES)
    def test_24_scalar_json_types_cannot_alias(self):
        observed=self.observed();m.one(m.sections(observed)['constraints'],lambda r:r['catalog']['oid']==IDS['fk'])['catalog']['conenforced']=1;self.reject(observed)
        observed=self.observed();m.one(m.sections(observed)['columns'],lambda r:r['catalog']['attrelid']==IDS['heap'])['catalog']['attnum']=True;self.reject(observed)
        self.assertFalse(m.raw_equal({'nested':[True]},{'nested':[1]}));self.assertFalse(m.raw_equal([1],[1.0]))
    def test_25_no_runtime_entrypoint_or_native_audit(self):
        for name in ('cases.py','protocol.py'):ast.parse((HERE/name).read_bytes())
        self.assertEqual(DENIED,[])

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CTAS))
    print(json.dumps(dict(testsRun=result.testsRun,successful=result.wasSuccessful(),nativeAuditEvents=DENIED,actualCTASCasesExecuted=0,fullS5Qualified=False)))
    raise SystemExit(0 if result.wasSuccessful() and not DENIED else 1)
