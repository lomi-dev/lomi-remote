"""Pure guard/comparison tests. No children, PG versions, connections or Node."""
from pathlib import Path
import ast
import importlib.util
import json
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fixture_driver', HERE / 'pg-s0-s4.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class SourceGuards(unittest.TestCase):
    def test_all_new_python_parses_without_bytecode(self):
        for name in ('pg-s0-s4.py', 'pg-s0-s4.test.py'):
            ast.parse((HERE / name).read_text())

    def test_raw_definition_digest_is_checked(self):
        row = dict(kind='function', definitionUtf8Hex=b'raw bytes\n'.hex(),
                   catalogSha256=driver.digest(b'raw bytes\n'))
        self.assertEqual(driver.parse_catalog(json.dumps(row)), [row])
        row['definitionUtf8Hex'] = b'raw bytes'.hex()
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            driver.parse_catalog(json.dumps(row))

    def test_raw_definition_whitespace_drift_is_not_accepted(self):
        self.assertNotEqual(driver.canonical([dict(kind='function', definitionUtf8Hex='0a')]),
                            driver.canonical([dict(kind='function', definitionUtf8Hex='20')]))

    def test_cross_database_internal_trigger_names_use_semantic_identity(self):
        one = dict(kind='trigger', internal=True, name='RI_ConstraintTrigger_a_123',
                   definition='raw OID name 123', constraint='same_fk', relation='child', function='f()', type=9, referencedRelation='parent', constraintIndex='parent_pkey',
                   columns='', whenTriggerDefinition=None, enabled='O', deferrable=False, deferred=False)
        two = dict(one, name='RI_ConstraintTrigger_a_456', definition='raw OID name 456')
        self.assertEqual(driver.canonical([one]), driver.canonical([two]))
        self.assertNotEqual(driver.canonical([one]), driver.canonical([dict(two, type=8)]))
        for field, value in [('referencedRelation', 'other'), ('constraintIndex', 'other'),
                             ('columns', '1'), ('whenTriggerDefinition', 'a > 0'), ('enabled', 'D'),
                             ('deferrable', True), ('deferred', True)]:
            self.assertNotEqual(driver.canonical([one]), driver.canonical([dict(two, **{field: value})]))
        self.assertEqual(one['definition'], 'raw OID name 123')

    def test_trigger_when_definition_keeps_old_new_and_fails_closed_for_internal_when(self):
        definition = 'CREATE TRIGGER same BEFORE UPDATE ON child FOR EACH ROW WHEN ((old.id IS DISTINCT FROM new.id)) EXECUTE FUNCTION guard()'
        ordinary = dict(kind='trigger', internal=False, name='same', definition=definition,
                        whenTriggerDefinition=definition, enabled='O', deferred=False, deferrable=False)
        original = json.dumps(ordinary, sort_keys=True)
        changed = definition.replace('IS DISTINCT FROM', 'IS NOT DISTINCT FROM')
        self.assertNotEqual(driver.canonical([ordinary]),
                            driver.canonical([dict(ordinary, definition=changed, whenTriggerDefinition=changed)]))
        self.assertNotEqual(driver.canonical([ordinary]),
                            driver.canonical([dict(ordinary, definition=changed)]))
        self.assertNotEqual(driver.canonical([ordinary]),
                            driver.canonical([dict(ordinary, whenTriggerDefinition=None)]))
        internal = dict(ordinary, internal=True, name='RI_ConstraintTrigger_a_123',
                        definition=definition.replace('same', 'RI_ConstraintTrigger_a_123'),
                        whenTriggerDefinition=definition.replace('same', 'RI_ConstraintTrigger_a_123'))
        other = dict(internal, name='RI_ConstraintTrigger_a_456',
                     definition=definition.replace('same', 'RI_ConstraintTrigger_a_456'),
                     whenTriggerDefinition=definition.replace('same', 'RI_ConstraintTrigger_a_456'))
        self.assertNotEqual(driver.canonical([internal]), driver.canonical([other]))
        self.assertEqual(json.dumps(ordinary, sort_keys=True), original)
        sql = (HERE / 'pg-s0-s4-metadata.sql').read_text()
        self.assertIn("'definition',pg_get_triggerdef(oid,false)", sql)
        self.assertIn("'whenTriggerDefinition',CASE WHEN tgqual IS NULL THEN NULL ELSE pg_get_triggerdef(oid,false) END", sql)
        self.assertNotIn('pg_get_expr(', sql)

    def test_unknown_and_privileged_grants_fail_closed(self):
        for row in [dict(kind='columnAcl', grantee='fixture_unexpected', grantor='e2_owner'),
                    dict(kind='defaultAcl', owner='e2_owner', grantee='fixture_unexpected', grantor='e2_owner'),
                    dict(kind='membership', role='lomi_migrator', member='lomi_runtime'),
                    dict(kind='schemaAuthority', role='lomi_migrator', create=True)]:
            with self.subTest(row=row), self.assertRaises(ValueError):
                driver.reject_authority_drift([row])

    def test_closed_relation_map_compares_cross_database_oids_without_changing_raw_acl(self):
        def identities(start):
            return [dict(kind='relationIdentity', oid=str(start + i), catalogKey=name,
                         schema=schema, name=name)
                    for i, (schema, name) in enumerate(sorted(driver.PROTECTED_RELATIONS))]
        one, two = identities(100), identities(200)
        first, second = driver.protected_relation_map(one), driver.protected_relation_map(two)
        row = dict(kind='protectedAcl', relation='100', column='id', tableAcl='{owner=arwdDxt/owner}')
        other = dict(row, relation='200')
        self.assertEqual(driver.canonical([row], first), driver.canonical([other], second))
        self.assertEqual(row['relation'], '100')
        self.assertNotEqual(driver.canonical([row], first), driver.canonical([dict(other, relation='201')], second))
        self.assertNotEqual(driver.canonical([row], first),
                            driver.canonical([dict(other, tableAcl='{PUBLIC=r/owner}')], second))
        self.assertEqual(driver.canonical([row], first),
                         driver.canonical([dict(other, relation=two[0]['catalogKey'])], second))
        for rows in [one + [one[0]], one[:-1],
                     [dict(one[0], name='unknown'), *one[1:]],
                     [dict(one[0], oid=one[1]['oid']), *one[1:]]]:
            with self.assertRaises(ValueError):
                driver.protected_relation_map(rows)
        with self.assertRaises(ValueError):
            driver.canonical([dict(row, relation='999')], first)
        with self.assertRaises(ValueError):
            driver.canonical([row])

    def test_role_attribute_recipes_are_bound_to_frozen_public_sources(self):
        prep_hashes = json.loads(driver.checked(driver.PLAN / 'preparation-source-sha256.json', driver.PREP_HASH))
        lock = json.loads(driver.checked(driver.PLAN / 'qualification-source/inputs.lock.json',
                                         prep_hashes['inputs.lock.json']))
        for name, statements in driver.ROLE_SOURCE_STATEMENTS.items():
            data = driver.checked(driver.PLAN / 'frozen-public' / name, lock['publicArchiveMembers'][name])
            self.assertTrue(all(statement.encode() in data for statement in statements))
        harness = 'test/run_host_credentials_runtime.py'
        self.assertIn(driver.ROLE_SQL.encode(), driver.checked(driver.PLAN / 'frozen-public' / harness,
                                                              lock['publicArchiveMembers'][harness]))
        manifest = json.loads(driver.checked(driver.ROOT / lock['candidateManifest']['path'],
                                             lock['candidateManifest']['sha256']))
        helper = 'operator-seal-auth-helpers.candidate.sql'
        data = driver.checked(driver.ROOT / 'staging/consumer-derivatives-v2' / helper, manifest[helper])
        self.assertIn(('CREATE ROLE lomi_consumer_auth_body_owner' + driver.SEALED_ROLE_SUFFIX).encode(), data)

    def test_exact_synthetic_role_login_inherit_and_config_are_checked(self):
        for name in sorted(driver.ROLES):
            row = dict(kind='role', name=name, **driver.expected_role(name))
            driver.reject_authority_drift([row])
            for field, value in [('login', not row['login']), ('inherit', not row['inherit']),
                                 ('config', ['search_path=untrusted'])]:
                with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                    driver.reject_authority_drift([dict(row, **{field: value})])
        self.assertFalse(driver.expected_role('lomi_consumer_auth_body_owner')['inherit'])
        self.assertTrue(driver.expected_role('lomi_migrator')['inherit'])
        self.assertFalse(driver.expected_role('lomi_runtime')['inherit'])

    def test_evidence_write_failure_cannot_skip_owned_stop_or_status(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            (work / 'socket').mkdir()
            calls = []
            def run(argv, **kwargs):
                calls.append(argv[-1])
                return SimpleNamespace(returncode=3 if argv[-1] == 'status' else 0, stdout='', stderr='')
            fixture = driver.Fixture(SimpleNamespace(run_owned=run), {'toolchainRoot': 'unused'},
                                     work, work, 'test-only', Path('/unused'))
            fixture.start_attempted = True
            fixture.pid_identity = lambda: ['owned-identity']
            def full_disk(*args):
                raise OSError('injected full disk')
            fixture.save = full_disk
            result = fixture.cleanup()
            self.assertEqual(calls, ['stop', 'status'])
            self.assertTrue(result['completed'])
            self.assertEqual(len(fixture.evidence_errors), 2)

    def test_deadline_budget_uses_original_start_for_finalization(self):
        with patch.object(driver.time, 'monotonic', return_value=999):
            self.assertEqual(driver.remaining_budget(100), 1)
            with self.assertRaises(driver.AppointmentDeadline):
                driver.remaining_budget(100, 840)
        with patch.object(driver.time, 'monotonic', return_value=1000):
            with self.assertRaises(driver.AppointmentDeadline):
                driver.remaining_budget(100)

    def test_late_finalization_timeout_leaves_no_authoritative_success(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory).resolve()
            manifest = dict(status='PROVISIONAL_S4_PENDING_ROOT_REVIEW', authoritative=False,
                            runId=evidence.name, cleanup={'completed': True},
                            stages={stage: 'PASS' for stage in ('S0', 'S1', 'S2', 'S3', 'S4')})
            manifest_bytes = json.dumps(manifest).encode()
            (evidence / 'transition-manifest.json').write_bytes(manifest_bytes)
            fixture = SimpleNamespace(started=100, evidence=evidence)
            # The atomic receipt rename completes, then the original deadline
            # expires. The driver propagates an error and cannot exit zero.
            with patch.object(driver.time, 'monotonic', side_effect=[999, 1001]):
                with self.assertRaises(driver.AppointmentDeadline):
                    driver.publish_completion(fixture, driver.digest(manifest_bytes))
            receipt = json.loads((evidence / 'completion-receipt.json').read_text())
            self.assertFalse(json.loads((evidence / 'transition-manifest.json').read_bytes())['authoritative'])
            self.assertEqual(receipt['status'], 'REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO')
            self.assertFalse(driver.completion_is_admissible(manifest_bytes, receipt, {}))
            envelope = dict(runId=evidence.name, completed=True, ownedControllerExitCode=1,
                            originalOuterDeadlineSeconds=900, elapsedSeconds=899)
            self.assertFalse(driver.completion_is_admissible(manifest_bytes, receipt, envelope))
            self.assertFalse(driver.completion_is_admissible(manifest_bytes, receipt,
                              dict(envelope, ownedControllerExitCode=0, elapsedSeconds=901)))
            valid = dict(envelope, ownedControllerExitCode=0)
            self.assertTrue(driver.completion_is_admissible(manifest_bytes, receipt, valid))
            self.assertFalse(driver.completion_is_admissible(manifest_bytes, receipt,
                             dict(valid, ownedControllerExitCode=False)))
            self.assertFalse(driver.completion_is_admissible(manifest_bytes + b' ', receipt, valid))
            self.assertFalse(driver.completion_is_admissible(manifest_bytes, receipt, dict(valid, runId='other')))

    def test_actual_s0_admission_remains_static_and_admits_exact_frozen_inputs(self):
        lock, inputs, tools, support = driver.admit_sources()
        self.assertEqual(len(inputs['baselineFiles']), 28)
        self.assertEqual(len(inputs['candidateFiles']), 14)
        self.assertEqual(len(inputs['preparationFiles']), 8)
        self.assertEqual(len(tools), 49)
        self.assertEqual(support, driver.ROOT / 'tools/owned_process.py')
        prep_hashes = json.loads(inputs['preparationManifest'])
        for name, sha in prep_hashes.items():
            driver.checked(HERE / name, sha)
        driver.checked(HERE / 'reference-build.mjs', driver.CONSTRUCTOR_HASH)

    def test_empty_ledger_fixture_is_once_before_unchanged_frozen_ops(self):
        sql = driver.checked(HERE / 'pg-s0-s4-ledger-fixture.sql', driver.LEDGER_FIXTURE_HASH).decode()
        steps = [dict(id=('migration:' if i < 24 else 'baseline-ops:' if i < 30 else 'candidate:') + str(i),
                      sql='unchanged source bytes ' + str(i)) for i in range(36)]
        original = json.dumps(steps)
        schedule = driver.baseline_steps_with_ledger(steps, sql)
        self.assertEqual(schedule[:24], steps[:24])
        self.assertEqual(schedule[25:], steps[24:30])
        self.assertEqual(len(schedule), 31)
        self.assertEqual(schedule[24]['id'], 'fixture-only:empty-prisma-ledger:ONCE')
        self.assertEqual(schedule[24]['sql'], sql)
        self.assertFalse(schedule[24]['source']['prismaLedgerQualified'])
        self.assertEqual(json.dumps(steps), original)
        for database in driver.DATABASES:
            self.assertEqual(sum(step['id'].startswith('fixture-only:') for step in schedule), 1)
        with self.assertRaises(ValueError):
            driver.baseline_steps_with_ledger(steps, sql + '\nCREATE TABLE extra(id integer);')
        with self.assertRaises(ValueError):
            driver.baseline_steps_with_ledger(steps[1:], sql)

    def test_ledger_has_exact_documented_eight_columns_and_no_claimed_history(self):
        sql = (HERE / 'pg-s0-s4-ledger-fixture.sql').read_text()
        body = sql.split('CREATE TABLE public._prisma_migrations (', 1)[1].split(');', 1)[0]
        columns = [line.strip().rstrip(',') for line in body.strip().splitlines()]
        self.assertEqual(columns, ['id VARCHAR(36) PRIMARY KEY NOT NULL', 'checksum VARCHAR(64) NOT NULL',
                         'finished_at TIMESTAMPTZ', 'migration_name VARCHAR(255) NOT NULL', 'logs TEXT',
                         'rolled_back_at TIMESTAMPTZ', 'started_at TIMESTAMPTZ NOT NULL DEFAULT now()',
                         'applied_steps_count INTEGER NOT NULL DEFAULT 0'])
        statements = '\n'.join(line for line in sql.splitlines() if not line.startswith('--'))
        self.assertEqual(statements.count(';'), 2)
        self.assertEqual(statements.split(');', 1)[1].strip(), 'SELECT count(*) FROM public._prisma_migrations;')
        self.assertFalse(any(word in statements.upper() for word in ('INSERT', 'UPDATE', 'DELETE', 'ALTER', 'EXECUTE', 'IF NOT EXISTS')))

    def test_schema_only_psql_requests_actual_sqlstate_in_verbose_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            fixture = driver.Fixture(None, {'toolchainRoot': 'unused'}, work, work, 'test-only', Path('/unused'))
            argv = []
            fixture.command = lambda label, args: argv.extend(str(arg) for arg in args) or ''
            fixture.sql(driver.DATABASES[0], 'pure-client-options', 'SELECT 1;')
            self.assertIn('VERBOSITY=verbose', argv)
            self.assertIn('ON_ERROR_STOP=1', argv)
            self.assertIn('-X', argv)

    def test_predecessor_capture_selects_only_frozen_root_signatures(self):
        sql = driver.predecessor_query((HERE / 'catalog-discovery.sql').read_text())
        self.assertEqual(sql.count(" ('public."), 3)
        self.assertEqual(sql.count(';'), 1)
        self.assertNotIn('consumer_authorization)', sql)
        self.assertIn('definitionUtf8Hex', sql)
        for signature in driver.ROOT_SIGNATURES:
            self.assertIn(signature, sql)

    def test_checks_reject_symlinks_and_modified_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'source'
            path.write_bytes(b'original')
            self.assertEqual(driver.checked(path, driver.digest(b'original')), b'original')
            with self.assertRaises(ValueError):
                driver.checked(path, driver.digest(b'changed'))
            link = Path(directory).resolve() / 'link'
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                driver.checked(link)

    def test_owned_cleanup_identity_requires_every_bound_field(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / 'data').mkdir()
            (work / 'socket').mkdir()
            fixture = driver.Fixture(None, {'toolchainRoot': 'unused'}, work, work, 'test-only', Path('/unused'))
            pid = work / 'data/postmaster.pid'
            pid.write_text('12345\n' + str(work / 'data') + '\n123\n55439\n' + str(work / 'socket') + '\n\nshmem\nready\n')
            self.assertEqual(fixture.pid_identity()[0], '12345')
            pid.write_text(pid.read_text().replace('55439', '5432'))
            with self.assertRaises(ValueError):
                fixture.pid_identity()

    def test_owned_environment_is_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            fixture = driver.Fixture(None, {'toolchainRoot': 'unused'}, work, work, 'test-only', Path('/unused'))
            self.assertEqual(set(fixture.env), {'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'TZ'})
            self.assertEqual(fixture.env['HOME'], str(work / 'home'))


if __name__ == '__main__':
    unittest.main()
