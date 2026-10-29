"""Pure source regressions; no SQL parse or permission claims."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import unittest

HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

h=load('owner_fault_harness',HERE/'s5.py');b=load('owner_fault_builder',HERE/'cases.py')

class OwnerFaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c=h.load_constructor();cls.admitted=cls.c.load_admitted();cls.rows=cls.admitted[3]['new']['catalog']
        cls.prior=load('owner_fault_prior',h.PRIOR/'s5.py');cls.cases=b.build(cls.rows,cls.prior.denied_sql)

    def test_closed120_case_matrix(self):
        self.assertEqual(len(self.cases),120);self.assertEqual(len({c['id'] for c in self.cases}),120)
        for role in b.ROLES:
            for sig in b.SIGNATURES:
                self.assertEqual({c['action'] for c in self.cases if c['role']==role and c['signature']==sig},{'bypass-body','security-flip','search-path','owner','rename','drop-cascade'})
        self.assertEqual(self.cases,b.build(self.rows,self.prior.denied_sql))

    def test_bypass_body_header_exact_body_skips_checks(self):
        functions={r['signature']:r for r in self.rows if r.get('kind')=='function'}
        for case in self.cases:
            if case['action']!='bypass-body':continue
            raw=bytes.fromhex(functions[case['signature']]['definitionUtf8Hex']).decode()
            oldhead,oldbody,oldtail=raw.split('$function$');head,body,tail=case['statement'].split('$function$')
            self.assertEqual(oldhead,head);self.assertEqual(oldtail,tail);self.assertNotEqual(oldbody,body)
            self.assertIn('BEGIN RETURN',body);self.assertNotIn('PERFORM',body);self.assertNotIn('IF ',body)
            if case['signature'] in b.JSON_RETURNS:self.assertIn('"fixtureBypass":true',body)
            else:self.assertEqual(body,'\nBEGIN RETURN; END;\n')

    def test_security_changes_mode(self):
        functions={r['signature']:r for r in self.rows if r.get('kind')=='function'}
        for case in self.cases:
            if case['action']=='security-flip':
                self.assertIn('SECURITY '+('INVOKER' if functions[case['signature']]['securityDefiner'] else 'DEFINER'),case['statement'])

    def test_changed_config_owner_name_and_cascade(self):
        for case in self.cases:
            sql=case['statement']
            if case['action']=='search-path':self.assertTrue(sql.endswith('SET search_path TO public, pg_catalog, pg_temp;'))
            if case['action']=='owner':self.assertTrue(sql.endswith('OWNER TO '+case['role']+';'))
            if case['action']=='rename':self.assertIn(' RENAME TO fixture_denied_',sql)
            if case['action']=='drop-cascade':self.assertEqual(sql,'DROP FUNCTION '+case['signature']+' CASCADE;')

    def test_exact42501_only_and_full_statement_hash(self):
        for case in self.cases:
            self.assertEqual(case['expectedSqlstate'],'42501');self.assertIn("EXCEPTION WHEN SQLSTATE '42501'",case['sql'])
            self.assertNotIn('WHEN OTHERS',case['sql']);self.assertIn('SET SESSION AUTHORIZATION '+case['role'],case['sql'])
            self.assertEqual(hashlib.sha256(case['statement'].encode()).hexdigest(),case['statementSha256'])

    def test_source_substitution_duplicate_missing_rejected(self):
        rows=copy.deepcopy(self.rows);row=next(r for r in rows if r.get('signature')==b.SIGNATURES[0]);row['definitionUtf8Hex']+='20'
        with self.assertRaises(ValueError):b.build(rows,self.prior.denied_sql)
        row=next(r for r in self.rows if r.get('signature')==b.SIGNATURES[0])
        with self.assertRaises(ValueError):b.build(self.rows+[row],self.prior.denied_sql)
        with self.assertRaises(ValueError):b.build([r for r in self.rows if r.get('signature')!=b.SIGNATURES[0]],self.prior.denied_sql)

    def test_subset_gate_rejects_promotion_or_missing_new_group(self):
        manifest={'status':'PROVISIONAL_S5_SUBSET_PENDING_ROOT_REVIEW','authoritative':False,'cleanup':{'completed':True},
          'originalInputsUnchanged':True,'evidenceWriteErrors':[],'stages':{**{s:'PASS' for s in ('S0','S1','S2','S3','S4')},'S5':'SUBSET_PASS'},
          'fullS5Qualified':False,'boundedSubsetCompleted':True,'qualification':{'S5':False},'ownerFaultsCompleted':True,'ownerFaultCount':120,'runId':'test'}
        controller={'runId':'test','completed':True,'ownedControllerExitCode':0,'originalOuterDeadlineSeconds':900,'elapsedSeconds':2}
        def gate(m,control=controller):
            raw=json.dumps(m).encode();receipt={'status':'REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO','manifestSha256':hashlib.sha256(raw).hexdigest(),'runId':'test','requiresOwnedControllerExitCode':0,'originalOuterDeadlineSeconds':900}
            return h.completion_is_admissible(raw,receipt,control)
        self.assertTrue(gate(manifest))
        for update in [lambda m:m['stages'].update(S5='PASS'),lambda m:m.update(fullS5Qualified=True),lambda m:m.pop('ownerFaultsCompleted'),lambda m:m.update(ownerFaultCount=76),lambda m:m.update(ownerFaultCount=True),lambda m:m.pop('boundedSubsetCompleted')]:
            mutated=copy.deepcopy(manifest);update(mutated);self.assertFalse(gate(mutated))
        self.assertFalse(gate(manifest,{}));self.assertFalse(gate(manifest,{**controller,'elapsedSeconds':900}))

    def test_pristine_predecessor_and_drift_not_executed(self):
        plan=json.loads((HERE/'next-plan.json').read_bytes())
        self.assertEqual(plan['status'],'PLANNED_NOT_RUN');self.assertFalse(plan['runtimeAdmitted'])
        self.assertTrue(all(group['status']=='NOT_RUN' for group in plan['groups']))
        self.assertNotIn('pg_proc SET', '\n'.join(c['statement'] for c in self.cases))

if __name__=='__main__':unittest.main()
