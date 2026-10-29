"""Pure deterministic recipe/snapshot/error admission tests; no SQL parsing."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import unittest

HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

h=load('op_harness',HERE/'s5.py');m=load('op_cases',HERE/'cases.py')

class OperatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c=h.load_constructor();cls.a=cls.c.load_admitted();cls.refs=cls.a[3];cls.cases=m.build(cls.refs)
        cls.prior=load('op_prior',h.PRIOR/'s5.py');cls.base=load('op_base',cls.c.ROOT/cls.a[0]['driver'])
        cls.roles={name:i+100 for i,name in enumerate(sorted(cls.base.ROLES))}
        cls.operators=cls.c.construct()[0]

    def test_closed16_baselines(self):
        self.assertEqual(len(self.cases),16);self.assertEqual(self.cases,m.build(self.refs))
        self.assertEqual(len({c['id'] for c in self.cases}),16)
        self.assertTrue(all(c['database']==0 and c['baseline']=='old' for c in self.cases if c['signature'] is not None and (c['id'].startswith('helper-') or c['id']=='mixed-one-of-two-helpers')))
        self.assertTrue(all(c['baseline']=='new' and c['database']==2 for c in self.cases if c['id'].startswith('root-') or c['id'].startswith('mixed-one-of-three') or c['signature'] is None))

    def test_unchanged_operator_suffix_and_setup_first(self):
        for c in self.cases:
            op=self.operators['operator-seal-auth-helpers.candidate.sql' if c['operator']=='helper' else 'operator-three-roots.candidate.sql'].decode()
            script=m.branch_sql(c,'SELECT catalog;','SELECT metadata;',op)
            self.assertEqual(script.count(op),1);self.assertTrue(script.startswith('BEGIN;\n'+c['setupSql']))
            self.assertLess(script.index(c['id']+':META_END'),script.index(op));self.assertIn(c['id']+':OPERATOR_BEGIN',script)
            self.assertIn("SELECT '"+c['id']+":UNEXPECTED_ACCEPTANCE';",script[script.index(op)+len(op):])
            self.assertTrue(op.rstrip().endswith('COMMIT;'))

    def test_expected_mixed_states_exact(self):
        new=m.function_map(self.refs['new']['catalog']);old=m.function_map(self.refs['old']['catalog'])
        c=next(c for c in self.cases if c['mutation']=='mixed-helper');actual=m.function_map(m.expected_setup(c,self.refs,self.roles)['catalog'])
        self.assertEqual(actual[m.HELPER],new[m.HELPER]);self.assertEqual(sum(actual[s]!=old[s] for s in old),1)
        c=next(c for c in self.cases if c['mutation']=='mixed-root');actual=m.function_map(m.expected_setup(c,self.refs,self.roles)['catalog'])
        self.assertEqual(actual[m.ROOT],new[m.ROOT]);self.assertEqual(sum(actual[s]!=new[s] for s in new),2)

    def test_each_declared_setup_differs_and_has_no_extra_changes(self):
        for c in self.cases:
            pristine=copy.deepcopy(self.refs[c['baseline']]);actual=m.expected_setup(c,self.refs,self.roles)
            self.assertNotEqual(actual,pristine)
            if c['signature'] is not None:
                before=m.function_map(pristine['catalog']);after=m.function_map(actual['catalog'])
                changed={s for s in before if before[s]!=after[s]}
                if c['mutation'] not in ('mixed-helper','mixed-root'):self.assertEqual(changed,{c['signature']})
                self.assertEqual(pristine['metadata'],actual['metadata'])
            if c['mutation'].startswith('membership-'):
                role,member=(m.BODY_OWNER,'lomi_runtime') if c['mutation']=='membership-in' else ('lomi_runtime',m.BODY_OWNER)
                membership={'kind':'membership','role':role,'member':member,'admin':False,'inherit':False,'set':True}
                self.assertEqual(actual['catalog'],[*pristine['catalog'],membership])
                self.assertEqual(actual['metadata'],[*pristine['metadata'],membership])
                self.assertIsNot(actual['catalog'][-1],actual['metadata'][-1])
                self.assertEqual(self.refs[c['baseline']],pristine)

    def test_raw_definition_consistency_for_predicted_setup(self):
        for c in self.cases:m.function_map(m.expected_setup(c,self.refs,self.roles)['catalog'])
        for c in [c for c in self.cases if c['mutation']=='config']:
            row=m.function_map(m.expected_setup(c,self.refs,self.roles)['catalog'])[c['signature']]
            self.assertEqual(row['config'][-1],'work_mem=8MB');self.assertIn(b" SET work_mem TO '8MB'\nAS $function$",bytes.fromhex(row['definitionUtf8Hex']))

    def test_role_oid_map_closed_duplicates_unknown_rejected(self):
        rows=[{'role':name,'oid':oid} for name,oid in self.roles.items()];self.assertEqual(m.validate_role_oids(rows,self.base.ROLES),self.roles)
        for bad in (rows[:-1],rows+[rows[0]],[*rows[:-1],{'role':'unreviewed','oid':999}], [*rows[:-1],{'role':rows[-1]['role'],'oid':rows[0]['oid']}]):
            with self.assertRaises(ValueError):m.validate_role_oids(bad,self.base.ROLES)

    def output(self,c):
        tags=m.markers(c['id']);rows=json.dumps({'kind':'fixture-test'})
        return '\n'.join([tags[0],rows,tags[1],tags[2],rows,tags[3],tags[4],''])

    def test_exact_error_and_complete_setup_markers(self):
        for c in self.cases:
            out=self.output(c);err='WARNING: 25001: there is already a transaction in progress\nERROR: P0001: '+c['expectedGuardMessage']+'\nCONTEXT: test'
            capture=m.parse_result(c,out,err,self.base.parse_catalog);self.assertEqual(len(capture['catalog']),1)
            for wrong in ('ERROR: 42501: '+c['expectedGuardMessage'],'ERROR: P0001: earlier setup error',err+'\nERROR: P0001: duplicate'):
                with self.assertRaises(ValueError):m.parse_result(c,out,wrong,self.base.parse_catalog)
            for tag in m.markers(c['id'])[:5]:
                with self.assertRaises(ValueError):m.parse_result(c,out.replace(tag,'MISSING'),err,self.base.parse_catalog)
            with self.assertRaises(ValueError):m.parse_result(c,out+'\n'+m.markers(c['id'])[-1],err,self.base.parse_catalog)

    def test_wrong_setup_cannot_count_as_guard_success(self):
        c=next(c for c in self.cases if c['mutation']=='body');expected=m.expected_setup(c,self.refs,self.roles)
        with self.assertRaises(ValueError):self.prior.compare_capture(self.base,self.refs[c['baseline']]['catalog'],self.refs[c['baseline']]['metadata'],expected)

    def test_guard_messages_present_in_frozen_source(self):
        for c in self.cases:
            op=self.operators['operator-seal-auth-helpers.candidate.sql' if c['operator']=='helper' else 'operator-three-roots.candidate.sql'].decode()
            source_message=c['expectedGuardMessage']
            if c['signature'] and source_message.endswith(c['signature']):source_message=source_message[:-len(c['signature'])]+'%'
            if source_message.endswith(m.BODY_OWNER):source_message=source_message[:-len(m.BODY_OWNER)]+'%'
            self.assertIn("RAISE EXCEPTION '"+source_message+"'",op)

    def test_subset_gate_requires16_and_no_full_promotion(self):
        d={'status':'PROVISIONAL_S5_SUBSET_PENDING_ROOT_REVIEW','authoritative':False,'cleanup':{'completed':True},'originalInputsUnchanged':True,'evidenceWriteErrors':[],
          'stages':{**{s:'PASS' for s in ('S0','S1','S2','S3','S4')},'S5':'SUBSET_PASS'},'fullS5Qualified':False,'boundedSubsetCompleted':True,'qualification':{'S5':False},'operatorFaultsCompleted':True,'operatorFaultCount':16,'runId':'test'}
        e={'runId':'test','completed':True,'ownedControllerExitCode':0,'originalOuterDeadlineSeconds':900,'elapsedSeconds':2}
        def gate(d,e=e):
            raw=json.dumps(d).encode();receipt={'status':'REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO','manifestSha256':hashlib.sha256(raw).hexdigest(),'runId':'test','requiresOwnedControllerExitCode':0,'originalOuterDeadlineSeconds':900};return h.completion_is_admissible(raw,receipt,e)
        self.assertTrue(gate(d))
        for change in (lambda d:d['stages'].update(S5='PASS'),lambda d:d.update(fullS5Qualified=True),lambda d:d.pop('operatorFaultsCompleted'),lambda d:d.update(operatorFaultCount=15),lambda d:d.update(operatorFaultCount=True)):
            bad=copy.deepcopy(d);change(bad);self.assertFalse(gate(bad))
        self.assertFalse(gate(d,{}));self.assertFalse(gate(d,{**e,'elapsedSeconds':900}))

if __name__=='__main__':unittest.main()
