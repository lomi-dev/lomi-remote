"""Python-only v2 source and synthetic predecessor regressions. No SQL execution."""
from pathlib import Path
import ast
import copy
import hashlib
import importlib.util
import json
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
STAGE = ROOT / 'staging/consumer-derivatives-v2'
OLD = ROOT / 'staging/consumer-derivatives'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


model = module('v2_predecessor_model', 'predecessor-model.py')
driver = module('v2_fixture_driver', 'pg-s0-s4.py')
contract = json.loads((STAGE / 'predecessor-contract.json').read_bytes())


class SuccessorSourceTests(unittest.TestCase):
    def test_exact_successor_admission_and_source_substitution_rejects(self):
        manifest = (STAGE / 'candidate-source-sha256.json').read_bytes()
        hashes = json.loads(manifest)
        files = {name: (STAGE / name).read_bytes() for name in hashes}
        self.assertEqual(driver.admit_candidate_bytes(manifest, files), hashes)
        changed = dict(files); changed['012-derivative-authority.candidate.sql'] += b'\n-- substitution'
        with self.assertRaises(ValueError): driver.admit_candidate_bytes(manifest, changed)
        changed_hashes = dict(hashes); changed_hashes['012-derivative-authority.candidate.sql'] = hashlib.sha256(changed['012-derivative-authority.candidate.sql']).hexdigest()
        with self.assertRaises(ValueError): driver.admit_candidate_bytes(json.dumps(changed_hashes).encode(), changed)
        with self.assertRaises(ValueError): driver.admit_candidate_bytes(manifest, dict(files, unexpected=b'x'))
        with self.assertRaises(ValueError): driver.admit_candidate_bytes((OLD / 'candidate-source-sha256.json').read_bytes(), files)

    def test_candidate_delta_is_guard_case_grouping_and_derived_source_identity(self):
        original = json.loads((OLD / 'candidate-source-sha256.json').read_bytes())
        successor = json.loads((STAGE / 'candidate-source-sha256.json').read_bytes())
        self.assertEqual([name for name in original if original[name] != successor[name]], ['012-derivative-authority.candidate.sql', 'authority-core.candidate.sql', 'operator-seal-auth-helpers.candidate.sql'])
        old = (OLD / '012-derivative-authority.candidate.sql').read_text()
        new = (STAGE / '012-derivative-authority.candidate.sql').read_text()
        self.assertEqual(new, model.successor_sql(old, contract))
        self.assertNotIn('consumer_authorization_originId_check', new)
        self.assertIn('DROP CONSTRAINT "consumer_authorization_check"', new)
        self.assertEqual((STAGE / 'catalog-contract.pending.json').read_bytes(), (OLD / 'catalog-contract.pending.json').read_bytes())
        old_pending = (OLD / 'helper-seal.pending.json').read_text()
        new_pending = (STAGE / 'helper-seal.pending.json').read_text()
        old_sha = json.loads(old_pending)['helpers'][0]['source_sha256']
        new_sha = json.loads(new_pending)['helpers'][0]['source_sha256']
        self.assertEqual(new_pending, old_pending.replace(old_sha, new_sha, 1))
        self.assertEqual((STAGE / 'operator-seal-auth-helpers.candidate.sql').read_text(),
                         (OLD / 'operator-seal-auth-helpers.candidate.sql').read_text().replace(old_sha, new_sha, 1))
        self.assertEqual((STAGE / 'authority-core.candidate.sql').read_text(),
                         model.group_authority_case((OLD / 'authority-core.candidate.sql').read_text()))
        for helper in json.loads(new_pending)['helpers']:
            self.assertTrue(all(helper[key] is None for key in ('old_catalog_sha256','new_catalog_sha256','old_acl','new_acl')))

    def test_measured_authority_failure_gets_exactly_two_grouping_bytes(self):
        history = ROOT / 'artifacts/consumer-derivatives-v2-source-history/1cdbae82-1ad6-4c96-aa52-f4f8e01672a5/reviewed-candidate'
        old = (history / 'authority-core.candidate.sql').read_text()
        new = (STAGE / 'authority-core.candidate.sql').read_text()
        self.assertIn(model.AUTHORITY_CASE_BEFORE, old)
        self.assertIn(model.AUTHORITY_CASE_AFTER, new)
        self.assertEqual(new, model.group_authority_case(old))
        self.assertEqual(len(new.encode()), len(old.encode()) + 2)
        self.assertEqual(new.replace(model.AUTHORITY_CASE_AFTER, model.AUTHORITY_CASE_BEFORE, 1), old)
        with self.assertRaises(ValueError): model.group_authority_case(new)
        self.assertEqual(new.count('CASE '), 3)
        for line in new.splitlines():
            if 'CASE ' in line: self.assertIn('(CASE ', line)
        proof_path = ROOT / 'artifacts/consumer-derivatives-v2-controller/2699c14d-b1fd-4698-82d0-fe1ea2c3c1b1/outer-tool-result.json'
        proof_bytes = proof_path.read_bytes()
        self.assertEqual(hashlib.sha256(proof_bytes).hexdigest(), '3f825a9b8d08814dee064a58c4dff951b477a13d3d1fdf905e0b2fc988d34e87')
        self.assertEqual(json.loads(proof_bytes)['measuredSqlstate'], '42601')
        pending = json.loads((STAGE / 'helper-seal.pending.json').read_bytes())
        start = new.index('CREATE FUNCTION public.lomi_consumer_principal_live_v2(')
        end = new.index('\nEND $$;', start) + len('\nEND $$;')
        self.assertEqual(hashlib.sha256(new[start:end].encode()).hexdigest(), pending['helpers'][0]['source_sha256'])
        lock = json.loads((HERE / 'inputs.lock.json').read_bytes())
        self.assertEqual(hashlib.sha256((STAGE / 'helper-seal.pending.json').read_bytes()).hexdigest(),
                         lock['candidateCatalogFiles']['helper-seal.pending.json'])
        self.assertIn(lock['candidateCatalogFiles']['helper-seal.pending.json'], (HERE / 'reference-build.mjs').read_text())

    def test_all_three_immutable_baseline_captures_have_actual_four_checks_and_fk(self):
        expected = {row['name']: row for row in contract['constraints']}
        for path, pin in contract['evidence']['baselineCaptures'].items():
            data = (ROOT / path).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), pin)
            rows = [r for r in json.loads(data) if r.get('kind') == 'constraint' and r.get('relation') == 'consumer_authorization']
            self.assertNotIn('consumer_authorization_originId_check', {row['name'] for row in rows})
            for row in rows:
                if row['name'] in expected:
                    self.assertEqual(row['definition'], expected[row['name']]['definition'])
                    self.assertTrue(row['validated']); self.assertFalse(row['deferrable']); self.assertFalse(row['deferred'])

    def test_ordered_check_vars_and_fk_columns_correlate_with_frozen_sql(self):
        lock, inputs, tools, support = driver.admit_sources()
        source = inputs['baselineFiles']['prisma/migrations/202610190004_consumer_authority/migration.sql'].decode()
        self.assertIn('"originId" text NOT NULL CHECK ("originId"="accountSessionId")', source)
        self.assertEqual(next(row['columns'] for row in contract['constraints']
                              if row['name'] == 'consumer_authorization_check'), ['originId', 'accountSessionId'])
        self.assertIn('FOREIGN KEY("accountSessionId","accountId","clientClass") REFERENCES public.remote_session_binding("sessionId","accountId","clientClass") ON DELETE CASCADE ON UPDATE NO ACTION', source)
        binding = inputs['baselineFiles']['prisma/migrations/202610190001_remote_enrollment_foundation/migration.sql'].decode()
        self.assertIn('UNIQUE("sessionId","accountId","clientClass")', binding)

    def test_exact_predecessor_and_unrelated_frozen_check_admitted(self):
        rows = copy.deepcopy(contract['constraints'])
        rows.append(dict(name='consumer_authorization_authorizationEpoch_check', type='c', columns=['authorizationEpoch']))
        before = copy.deepcopy(rows)
        self.assertTrue(model.admit_predecessors(rows, contract))
        self.assertEqual(rows, before)

    def test_each_check_identity_expression_columns_and_state_drift_rejects(self):
        for index, row in enumerate(contract['constraints']):
            if row['type'] != 'c': continue
            for key, value in [('name', row['name'] + '_renamed'), ('definition', 'CHECK (true)'),
                               ('columns', ['authorizationEpoch']), ('type', 'u'), ('validated', False),
                               ('enforced', False), ('deferrable', True), ('deferred', True), ('isLocal', False),
                               ('inheritCount', 1), ('noInherit', True), ('hasParent', True), ('period', True)]:
                rows = copy.deepcopy(contract['constraints']); rows[index][key] = value
                with self.subTest(name=row['name'], key=key), self.assertRaises(ValueError): model.admit_predecessors(rows, contract)
            rows = copy.deepcopy(contract['constraints']); rows.pop(index)
            with self.assertRaises(ValueError): model.admit_predecessors(rows, contract)

    def test_fk_target_order_actions_index_and_inheritance_state_drift_rejects(self):
        index = next(i for i, row in enumerate(contract['constraints']) if row['type'] == 'f')
        fk = contract['constraints'][index]
        changes = {'name': 'renamed_fk', 'type': 'c', 'definition': 'FOREIGN KEY (id) REFERENCES other(id)',
                   'columns': list(reversed(fk['columns'])), 'targetSchema': 'other', 'targetRelation': 'other',
                   'targetColumns': list(reversed(fk['targetColumns'])), 'updateAction': 'c', 'deleteAction': 'a',
                   'matchType': 'f', 'deleteSetColumns': ['accountId'], 'validated': False, 'enforced': False,
                   'deferrable': True, 'deferred': True, 'isLocal': False, 'inheritCount': 1,
                   'noInherit': False, 'hasParent': True, 'period': True, 'indexSchema': 'other',
                   'indexName': 'other', 'indexValid': False, 'indexReady': False, 'indexUnique': False,
                   'indexImmediate': False, 'indexLive': False, 'indexPrimary': True,
                   'indexPredicate': 'true', 'indexExpressions': 'id'}
        for key, value in changes.items():
            rows = copy.deepcopy(contract['constraints']); rows[index][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): model.admit_predecessors(rows, contract)

    def test_unexpected_duplicate_equivalent_checks_and_fk_rejects(self):
        for row in contract['constraints']:
            rows = copy.deepcopy(contract['constraints']); duplicate = copy.deepcopy(row); duplicate['name'] += '_extra'; rows.append(duplicate)
            with self.subTest(name=row['name']), self.assertRaises(ValueError): model.admit_predecessors(rows, contract)

    def test_class_binding_guard_rejects_extra_class_only_or_permuted_other_target_fk(self):
        fk = next(row for row in contract['constraints'] if row['type'] == 'f')
        extras = [dict(fk, name='fixture_client_class_only_fkey', columns=['clientClass'],
                       targetRelation='fixture_client_classes', targetColumns=['clientClass']),
                  dict(fk, name='fixture_reordered_class_binding_fkey',
                       columns=['clientClass', 'accountId', 'accountSessionId'],
                       targetRelation='fixture_class_triples', targetColumns=['clientClass', 'accountId', 'sessionId'])]
        for extra in extras:
            self.assertTrue(model.selected(extra, contract))
            with self.subTest(name=extra['name']), self.assertRaises(ValueError):
                model.admit_predecessors([*copy.deepcopy(contract['constraints']), extra], contract)
        sql = (STAGE / '012-derivative-authority.candidate.sql').read_text()
        self.assertIn("a.attnum=ANY(c.conkey)", sql)
        self.assertIn("AND a.attname IN ('originKind','originId','clientClass','canManageAccount')", sql)
        self.assertIn("=ARRAY['accountId','accountSessionId','clientClass']::text[]", sql)

    def test_extra_fk_on_each_transitioned_column_rejects_other_target(self):
        fk = next(row for row in contract['constraints'] if row['type'] == 'f')
        self.assertEqual(model.TRANSITION_FK_COLUMNS, {'originKind', 'originId', 'clientClass', 'canManageAccount'})
        for column in sorted(model.TRANSITION_FK_COLUMNS):
            extra = dict(fk, name='fixture_' + column + '_only_fkey', columns=[column],
                         targetRelation='fixture_' + column + '_domain', targetColumns=['value'])
            self.assertTrue(model.selected(extra, contract))
            with self.subTest(column=column), self.assertRaises(ValueError):
                model.admit_predecessors([*copy.deepcopy(contract['constraints']), extra], contract)

    def test_actual_frozen_account_and_session_fks_remain_outside_class_binding_guard(self):
        capture = next(iter(contract['evidence']['baselineCaptures']))
        rows = json.loads((ROOT / capture).read_bytes())
        actual = {row['name']: row for row in rows if row.get('kind') == 'constraint'
                  and row.get('relation') == 'consumer_authorization'}
        fk_shapes = [('consumer_authorization_accountId_userId_fkey', ['accountId', 'userId'],
                      'remote_account_identity', ['id', 'userId']),
                     ('consumer_authorization_accountSessionId_userId_fkey', ['accountSessionId', 'userId'],
                      'session', ['id', 'userId'])]
        preserved = []
        for name, columns, target, target_columns in fk_shapes:
            measured = actual[name]
            preserved.append(dict(name=name, type='f', columns=columns, targetSchema='public',
                                  targetRelation=target, targetColumns=target_columns,
                                  definition=measured['definition'], validated=measured['validated'],
                                  deferrable=measured['deferrable'], deferred=measured['deferred']))
        original = copy.deepcopy(preserved)
        for row in preserved: self.assertFalse(model.selected(row, contract))
        self.assertTrue(model.admit_predecessors([*copy.deepcopy(contract['constraints']), *preserved], contract))
        self.assertEqual(preserved, original)

    def test_transaction_guard_precedes_all_ddl_and_reapply_is_rejection(self):
        sql = (STAGE / '012-derivative-authority.candidate.sql').read_text()
        self.assertEqual(sql.count('\nBEGIN;\n'), 1); self.assertTrue(sql.rstrip().endswith('COMMIT;'))
        lock = sql.index("SELECT pg_advisory_xact_lock(")
        guard = sql.index('DO $v2_predecessor_guard$'); first_ddl = sql.index('ALTER TABLE')
        self.assertLess(lock, guard); self.assertLess(sql.index('END $v2_predecessor_guard$;'), first_ddl)
        self.assertIn("USING ERRCODE='55000'", sql)
        self.assertNotIn('IF EXISTS', sql[:first_ddl])
        self.assertIn('LOCK TABLE public.consumer_authorization IN ACCESS EXCLUSIVE MODE;', sql)
        self.assertIn('LOCK TABLE public.remote_session_binding IN SHARE MODE;', sql)
        # A synthetic post-state has none of the removed predecessor CHECK/FK
        # identities. Real rollback/reapply checks remain planned SQL work.
        with self.assertRaises(ValueError): model.admit_predecessors([], contract)

    def test_authority_contract_and_provenance_in_hash_closure_and_new_constructor(self):
        closure = driver.source_closure()
        for name, pin in driver.SUCCESSOR_EXTRA_HASHES.items(): self.assertEqual(closure[name], pin)
        source = (HERE / 'reference-build.mjs').read_text()
        self.assertIn(driver.SUCCESSOR_CANDIDATE_HASH, source)
        self.assertIn(driver.PREP_HASH, source)
        self.assertNotIn("candidateManifest: '2f932457", source)
        for path in HERE.iterdir():
            if path.suffix == '.py': ast.parse(path.read_text())


if __name__ == '__main__': unittest.main()
