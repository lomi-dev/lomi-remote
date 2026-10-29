"""Pure source/constructor regressions. No SQL parser or database claims."""
from pathlib import Path
import copy
import importlib.util
import json
import os
import stat
import tempfile
import uuid
import unittest
import unittest.mock
import unittest.mock

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

c=load('sealing_constructor','construct.py');s5=load('sealing_harness','s5.py')

class SealingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admitted=c.load_admitted();cls.output,cls.report=c.construct()
        spec=importlib.util.spec_from_file_location('test_base',c.ROOT/cls.admitted[0]['driver'])
        cls.base=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.base)

    def test_deterministic(self):
        self.assertEqual((self.output,self.report),c.construct())

    def test_s5_constructor_executes_the_buffer_it_hashes(self):
        seen=[];original_compile=compile
        def capture(source,*args,**kwargs):
            seen.append(source)
            return original_compile(source,*args,**kwargs)
        with unittest.mock.patch('builtins.compile',side_effect=capture):
            loaded=s5.load_constructor()
        self.assertEqual(len(seen),1)
        self.assertIsInstance(seen[0],bytes)
        self.assertEqual(c.sha(seen[0]),s5.CONSTRUCTOR_SHA)
        self.assertEqual(loaded.__file__,str(HERE/'construct.py'))

    def test_prerequisite_source_correlations_are_unique_and_owner_checked(self):
        lock,data,manifest,refs,contract,helper=self.admitted
        corr=self.report['prerequisiteSourceCorrelations']
        self.assertEqual(len(corr),24)
        self.assertEqual(set(corr),{p['signature'] for p in contract['prerequisites']})
        for sig,row in corr.items():
            self.assertTrue(row['ownerMatch'])
            self.assertTrue(row['candidateFunctionSourceSha256'])
            self.assertEqual(row['candidateFileSha256'],
                lock['sourceAndEvidenceSha256'][row['candidatePath']])
            self.assertIn('not asserted equal',row['correlationBasis'])
            self.assertEqual(row['declaredInputTypes'],
                c.signature_argument_types(sig))
        altered=copy.deepcopy(data);first=next(iter(corr.values()))
        altered[first['candidatePath']]+=b'\n'+c.extract_candidate_function(
            altered[first['candidatePath']],first['catalogSignature'].split('(',1)[0].split('.',1)[1])[0]
        maps={s:c.function_map(refs[s]['catalog'],{p['signature'] for p in contract['roots']+contract['prerequisites']}) for s in ('old','new')}
        with self.assertRaises(ValueError):c.prerequisite_source_correlations(altered,lock,contract,maps['new'])
        altered_contract=copy.deepcopy(contract)
        altered_contract['prerequisites'][0]['signature']=(
            altered_contract['prerequisites'][0]['signature']
            .replace('public.consumer_authorization','uuid'))
        with self.assertRaises(ValueError):c.prerequisite_source_correlations(data,lock,altered_contract,maps['new'])

    def test_root_sources_and_operator_literals_match_frozen_s4(self):
        lock,data,manifest,refs,contract,helper=self.admitted
        correlations=c.validate_root_source_correlations(data,lock,manifest,contract)
        self.assertEqual(len(correlations),3)
        self.assertEqual(set(correlations),{row['signature'] for row in contract['roots']})
        self.assertEqual(
            {row['predecessorSourceSha256'] for row in correlations.values()},
            {row['old_source_sha256'] for row in contract['roots']})
        inventory='public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)'
        self.assertEqual(correlations[inventory]['predecessorSourceSha256'],
                         manifest['sourceCorrelations']['predecessor'][0]['sourceSha256'])

        altered=copy.deepcopy(data)
        path=c.BASE+'lomi_consumer_inventory.old-source.sql'
        altered[path]=altered[path][:-1]+b' -- changed baseline\n'
        with self.assertRaises(ValueError):
            c.validate_root_source_correlations(altered,lock,manifest,contract)

        altered_manifest=copy.deepcopy(manifest)
        altered_manifest['sourceCorrelations']['predecessor'][0]['sourceSha256']='0'*64
        with self.assertRaises(ValueError):
            c.validate_root_source_correlations(data,lock,altered_manifest,contract)

        altered_manifest=copy.deepcopy(manifest)
        altered_manifest['sourceCorrelations']['rootLiterals'][0]['migration']=(
            altered_manifest['sourceCorrelations']['rootLiterals'][0]['migration']+'-changed')
        with self.assertRaises(ValueError):
            c.validate_root_source_correlations(data,lock,altered_manifest,contract)

        altered_contract=copy.deepcopy(contract)
        altered_contract['roots'][0]['new_source_sha256']='0'*64
        with self.assertRaises(ValueError):
            c.validate_root_source_correlations(data,lock,manifest,altered_contract)

        altered=copy.deepcopy(data)
        path=c.BASE+'operator-three-roots.candidate.sql'
        altered[path]=altered[path].replace(
            b'CREATE OR REPLACE FUNCTION public.lomi_consumer_inventory',
            b'CREATE OR REPLACE FUNCTION public.lomi_inventory_changed',1)
        with self.assertRaises(ValueError):
            c.validate_root_source_correlations(altered,lock,manifest,contract)

    def test_only_null_token_bytes_change(self):
        for name,raw in self.output.items():
            old=self.admitted[1][c.BASE+name];lastold=lastnew=0
            for d in self.report['files'][name]['deltas']:
                self.assertEqual(old[lastold:d['originalStart']],raw[lastnew:d['derivedStart']])
                self.assertEqual(old[d['originalStart']:d['originalEnd']],b'null')
                self.assertEqual(raw[d['derivedStart']:d['derivedEnd']].hex(),d['newHex'])
                self.assertEqual(d['correlation']['referenceState'] in ('old','new'),True)
                lastold=d['originalEnd'];lastnew=d['derivedEnd']
            self.assertEqual(old[lastold:],raw[lastnew:])
        self.assertEqual(sum(len(r['deltas']) for r in self.report['files'].values()),136)

    def test_original_nulls_remain(self):
        self.assertTrue(all(r[k] is None for r in self.admitted[5]['helpers'] for k in ('old_catalog_sha256','new_catalog_sha256','old_acl','new_acl')))
        self.assertEqual(len(c.null_spans(self.output['helper-seal.pending.json'].decode())),0)
        self.assertEqual(len(c.null_spans(self.output['catalog-contract.pending.json'].decode())),0)

    def test_duplicate_json_keys_and_extra_null_reject(self):
        with self.assertRaises(ValueError):c.null_spans('{"x":null,"x":null}')
        with self.assertRaises(ValueError):c.fill_json(b'{"x":null,"y":null}',{('x',):'a'},{('x',):{}})
        with self.assertRaises(ValueError):c.fill_json(b'{"x":"already"}',{('x',):'a'},{('x',):{}})

    def test_source_substitution_rejects(self):
        p=HERE/'construct.py'
        with self.assertRaises(ValueError):c.read_exact(p,'0'*64)
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp).resolve()/'target';target.write_bytes(b'pinned')
            alias=Path(tmp).resolve()/'alias';alias.symlink_to(target)
            with self.assertRaises((ValueError,OSError)):c.read_exact(alias,c.sha(b'pinned'))

    def test_input_ancestor_symlink_is_rejected_at_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();real=root/'real';real.mkdir()
            target=real/'target';target.write_bytes(b'pinned')
            alias=root/'alias';alias.symlink_to(real,target_is_directory=True)
            # Bypass the preliminary path check to exercise the dirfd walk.
            with unittest.mock.patch.object(Path,'is_symlink',return_value=False):
                with self.assertRaises(OSError):c.read_exact(alias/'target',c.sha(b'pinned'))

    def test_frozen_proof_chain_binds_run_hash_scope_and_empty_derivatives(self):
        lock,data,manifest,refs,contract,helper=self.admitted
        receipt,outer,root=[json.loads(data[p]) for p in lock['proofs'][1:]]
        raw=[data[p] for p in lock['proofs'][:3]]
        c.validate_frozen_evidence(manifest,receipt,outer,root,*raw)
        mutations=[
            lambda m,r,o,rr:(r.update(runId='other'),None,None),
            lambda m,r,o,rr:(None,o.update(fixtureRunId='other'),None),
            lambda m,r,o,rr:(None,None,rr.update(manifestSha256='0'*64)),
            lambda m,r,o,rr:(m.update(targetOldEquality={'catalog':False,'metadata':True}),None,None),
            lambda m,r,o,rr:(m.update(derivedCopies=['unexpected']),None,None),
            lambda m,r,o,rr:(m.update(derivedCopyDeltas=[{}]),None,None),
        ]
        for mutate in mutations:
            m,r,o,rr=copy.deepcopy((manifest,receipt,outer,root));mutate(m,r,o,rr)
            with self.assertRaises(ValueError):c.validate_frozen_evidence(m,r,o,rr,*raw)

    def test_output_admission_requires_dedicated_parent_uuid_and_no_symlink_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp).resolve()/'artifacts'/'consumer-derivatives-v2-sealing-derived'
            parent.mkdir(parents=True)
            good=parent/str(uuid.uuid4())
            self.assertEqual(c.validate_output_path(good,parent),good)
            self.assertEqual(c.validate_output_path(Path(os.path.relpath(good,Path.cwd())),parent),good)
            for bad in (parent/'not-a-uuid', parent/('{'+str(uuid.uuid4())+'}'),
                        Path(tmp)/str(uuid.uuid4())):
                with self.assertRaises(ValueError):c.validate_output_path(bad,parent)
            alias=Path(tmp)/'alias';alias.symlink_to(parent,target_is_directory=True)
            with self.assertRaises(ValueError):c.validate_output_path(alias/str(uuid.uuid4()),alias)
            aliased_ancestor=Path(tmp)/'linked-parent';aliased_ancestor.symlink_to(parent.parent,target_is_directory=True)
            with self.assertRaises(ValueError):c.validate_output_path(
                aliased_ancestor/parent.name/str(uuid.uuid4()),aliased_ancestor/parent.name)
            output_alias=parent/'alias-output';output_alias.symlink_to(good,target_is_directory=True)
            with self.assertRaises(ValueError):c.validate_output_path(output_alias,parent)

    def test_output_permissions_ignore_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();artifacts=root/'artifacts';artifacts.mkdir()
            parent=artifacts/'consumer-derivatives-v2-sealing-derived'
            directory=parent/str(uuid.uuid4());file=directory/'manifest.json'
            artifacts_mode=stat.S_IMODE(artifacts.stat().st_mode)
            old_umask=os.umask(0o777)
            output_fd=None
            try:
                output_fd=c.private_mkdir(directory)
                c.write_private('manifest.json',b'{}\n',output_fd)
            finally:
                if output_fd is not None:os.close(output_fd)
                os.umask(old_umask)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode),0o600)
            self.assertEqual(parent.stat().st_uid,os.getuid())
            self.assertEqual(stat.S_IMODE(artifacts.stat().st_mode),artifacts_mode)
            existing=artifacts/'existing-private-parent';existing.mkdir();os.chmod(existing,0o755)
            existing_fd=c.private_mkdir(existing/str(uuid.uuid4()));os.close(existing_fd)
            self.assertEqual(stat.S_IMODE(existing.stat().st_mode),0o700)

    def test_output_parent_ancestor_symlink_rejected_during_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();artifacts=root/'artifacts';artifacts.mkdir()
            parent=artifacts/'dedicated';alias=root/'artifacts-alias'
            alias.symlink_to(artifacts,target_is_directory=True)
            with self.assertRaises(OSError):c.private_mkdir(alias/'dedicated'/str(uuid.uuid4()))
            with self.assertRaises(ValueError):c.validate_output_path(
                alias/'dedicated'/str(uuid.uuid4()),alias/'dedicated')

    def test_missing_extra_duplicate_function_reject(self):
        rows=self.admitted[3]['old']['catalog'];sigs={r['signature'] for r in rows if r['kind']=='function'}
        for altered in ([r for r in rows if r.get('signature')!=sorted(sigs)[0]], rows+[next(r for r in rows if r['kind']=='function')]):
            with self.assertRaises(ValueError):c.function_map(altered,sigs)
        extra=copy.deepcopy(next(r for r in rows if r['kind']=='function'));extra['signature']='public.extra()'
        with self.assertRaises(ValueError):c.function_map(rows+[extra],sigs)

    def test_raw_definition_bytes_reject(self):
        rows=copy.deepcopy(self.admitted[3]['old']['catalog']);r=next(r for r in rows if r['kind']=='function');r['definitionUtf8Hex']+='20'
        with self.assertRaises(ValueError):c.function_map(rows,{r['signature'] for r in rows if r['kind']=='function'})

    def validate_mutation(self,mutator):
        refs=copy.deepcopy(self.admitted[3]);mutator(refs)
        with self.assertRaises(ValueError):c.validate_references(self.base,refs,self.admitted[4],self.admitted[5])

    def test_mixed_root_reject(self):
        sig=self.admitted[4]['roots'][0]['signature']
        def mutate(refs):
            old=next(r for r in refs['old']['catalog'] if r.get('signature')==sig)
            refs['new']['catalog']=[old if r.get('signature')==sig else r for r in refs['new']['catalog']]
        self.validate_mutation(mutate)

    def test_helper_body_config_owner_acl_drift_reject(self):
        sig=self.admitted[5]['helpers'][0]['signature']
        for key,value in [('owner','lomi_runtime'),('config',['search_path=public']),('acl',[])]:
            def mutate(refs,key=key,value=value):
                row=next(r for r in refs['new']['catalog'] if r.get('signature')==sig)
                # ACL transition is admitted only by exact file hash at IO boundary.
                if key=='acl':
                    row=next(r for r in refs['new']['catalog'] if r.get('signature')==self.admitted[4]['roots'][0]['signature'])
                row[key]=value
            self.validate_mutation(mutate)

    def test_role_default_column_metadata_drift_reject(self):
        mutations=[lambda r:r['new']['metadata'].append({'kind':'defaultAcl','grantee':'unexpected','owner':'lomi_migrator','grantor':'lomi_migrator'}),
                   lambda r:r['new']['metadata'].append({'kind':'columnAcl','grantee':'unexpected','grantor':'e2_owner'}),
                   lambda r:r['new']['metadata'].append({'kind':'schemaAuthority','role':'lomi_runtime','create':True}),
                   lambda r:r['new']['metadata'].append({'kind':'membership','role':'lomi_remote_inventory_owner','member':'lomi_runtime'}),
                   lambda r:r['new']['metadata'].append({'kind':'constraint','relation':'x','definition':'changed'})]
        for mutation in mutations:self.validate_mutation(mutation)

    def test_json_operator_bodies_outside_delimiters_unchanged(self):
        for name,tags in [('operator-seal-auth-helpers.candidate.sql',['$helper_pins$']),('operator-three-roots.candidate.sql',['$pins$','$deps$'])]:
            def strip(raw):
                for tag in tags:
                    a,body,b=raw.split(tag.encode());raw=a+tag.encode()+b'JSON'+tag.encode()+b
                return raw
            self.assertEqual(strip(self.output[name]),strip(self.admitted[1][c.BASE+name]))

    def test_owner_denials_use_real_roles_and42501_only(self):
        cases=s5.denial_cases(self.admitted[3]['new']['catalog']);self.assertEqual(len(cases),76)
        for label,sql in cases:
            self.assertIn('SET SESSION AUTHORIZATION lomi_',sql)
            self.assertIn("EXCEPTION WHEN SQLSTATE '42501'",sql)
            self.assertNotIn('WHEN OTHERS',sql)
        self.assertNotIn('pg_catalog.', '\n'.join(sql for _,sql in cases))

    def test_completion_needs_independent_exit_and_deadline(self):
        manifest={'status':'PROVISIONAL_S5_SUBSET_PENDING_ROOT_REVIEW','authoritative':False,'cleanup':{'completed':True},'originalInputsUnchanged':True,'evidenceWriteErrors':[],'runId':'test','stages':{**{s:'PASS' for s in ('S0','S1','S2','S3','S4')},'S5':'SUBSET_PASS'},'fullS5Qualified':False,'boundedSubsetCompleted':True,'qualification':{'S5':False}}
        raw=json.dumps(manifest).encode();receipt={'status':'REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO','manifestSha256':c.sha(raw),'runId':'test','requiresOwnedControllerExitCode':0,'originalOuterDeadlineSeconds':900};controller={'runId':'test','completed':True,'ownedControllerExitCode':0,'originalOuterDeadlineSeconds':900,'elapsedSeconds':2}
        self.assertTrue(s5.completion_is_admissible(raw,receipt,controller))
        for updates in ({'ownedControllerExitCode':1},{'elapsedSeconds':900},{'completed':False},{'runId':'other'}):
            self.assertFalse(s5.completion_is_admissible(raw,receipt,{**controller,**updates}))
        self.assertFalse(s5.completion_is_admissible(raw,receipt,{}))

    def test_full_s5_promotion_or_missing_distinctions_rejected(self):
        manifest={'status':'PROVISIONAL_S5_SUBSET_PENDING_ROOT_REVIEW','authoritative':False,
            'cleanup':{'completed':True},'originalInputsUnchanged':True,'evidenceWriteErrors':[],
            'runId':'test','stages':{**{s:'PASS' for s in ('S0','S1','S2','S3','S4')},'S5':'SUBSET_PASS'},
            'fullS5Qualified':False,'boundedSubsetCompleted':True,'qualification':{'S5':False}}
        controller={'runId':'test','completed':True,'ownedControllerExitCode':0,'originalOuterDeadlineSeconds':900,'elapsedSeconds':2}
        mutations=[lambda m:m['stages'].update(S5='PASS'),lambda m:m.update(fullS5Qualified=True),
            lambda m:m.pop('fullS5Qualified'),lambda m:m.pop('boundedSubsetCompleted'),
            lambda m:m.update(boundedSubsetCompleted=False),lambda m:m['qualification'].update(S5=True),
            lambda m:m.pop('qualification'),lambda m:m['stages'].update(S5='INCOMPLETE')]
        for mutate in mutations:
            altered=copy.deepcopy(manifest);mutate(altered);raw=json.dumps(altered).encode()
            # Matching receipt and exit0 do not admit a promoted or ambiguous stage.
            receipt={'status':'REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO','manifestSha256':c.sha(raw),
                'runId':'test','requiresOwnedControllerExitCode':0,'originalOuterDeadlineSeconds':900}
            self.assertFalse(s5.completion_is_admissible(raw,receipt,controller))

if __name__=='__main__':unittest.main()
