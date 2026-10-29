"""Pure, small filesystem tests. Fake runner; no child/process/PG launches."""
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CHILD_ATTEMPTS = []


def no_children(event, args):
    if event in ('subprocess.Popen', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.exec', 'os.system'):
        CHILD_ATTEMPTS.append(event)
        raise AssertionError('pure recorder tests prohibit child launches')


sys.addaudithook(no_children)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


r = load('evidence_recording_test_module', HERE / 'recording.py')
base = load('evidence_frozen_fixture_test_module', ROOT / 'tests/consumer-derivatives-v2/pg-s0-s4.py')


class RecorderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='evidence-pure-')
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name).resolve()
        self.addCleanup(lambda: self.assertEqual(CHILD_ATTEMPTS, []))

    def store(self, **kwargs):
        return r.EvidenceStore(self.parent / ('run-' + str(len(list(self.parent.iterdir())))), **kwargs)

    def reader(self, store):
        hashes = store.seal()
        return r.EvidenceReader(store.root, expected_index_sha256=hashes['storage-index.json'])

    def fixture(self, store, scope=''):
        work = self.parent / ('work-' + (scope or 'default')); work.mkdir(mode=0o700)
        (work / 'socket').mkdir(mode=0o700); (work / 'data').mkdir(mode=0o700)
        calls = []
        def fake_run(argv, **kwargs):
            calls.append(tuple(argv))
            if argv[-1] == 'stop':
                (work / 'data/postmaster.pid').unlink()
                return SimpleNamespace(stdout='stopped\n', stderr='', returncode=0)
            if argv[-1] == 'status':
                return SimpleNamespace(stdout='no server\n', stderr='', returncode=3)
            return SimpleNamespace(stdout=self.output, stderr=self.stderr, returncode=0)
        self.output, self.stderr = '', ''
        f = r.fixture_class(base.Fixture)(SimpleNamespace(run_owned=fake_run),
            {'toolchainRoot': 'unused-test-toolchain'}, work, store.scope(scope),
            'pure-test-no-runtime', Path('/not-executed-node'), recording_store=store,
            recording_scope=scope)
        return f, calls

    def test_unicode_newlines_actual_returns_and_cleaned_vs_sql(self):
        store = self.store(threshold=16)
        f, calls = self.fixture(store)
        self.output = 'α\r\n' + str(f.work) + '\n' + str(ROOT) + '\n' + 'x' * 100
        self.stderr = 'ERROR:  55000: exact guard\n'
        original = self.output
        self.assertEqual(f.sql(base.DATABASES[0], 'measured', 'SELECT actual;'), original)
        self.assertEqual(f.events[-1]['stderr'], self.stderr)
        reader = self.reader(store)
        self.assertTrue(reader.validate())
        command = reader.read('commands.json')[0]
        self.assertEqual(command['stdout'], original.replace(str(f.work), '<owned>').replace(str(ROOT), '<repo>'))
        self.assertEqual(reader.read('sql-1.json')['stdout'], original)
        self.assertNotEqual(command['stdout'], original)
        self.assertEqual(len(calls), 1)

    def test_capture_preserves_rows_definition_hex_and_exact_json(self):
        store = self.store(threshold=8); f, _ = self.fixture(store)
        definition = 'CREATE FUNCTION exact() RETURNS text AS $$α\n$$ LANGUAGE sql;'
        row = dict(kind='function', definitionUtf8Hex=definition.encode().hex(),
                   catalogSha256=hashlib.sha256(definition.encode()).hexdigest())
        self.output = json.dumps(row) + '\n'
        self.assertEqual(f.capture(base.DATABASES[0], 'actual-catalog', 'SELECT measured;'), [row])
        self.assertEqual((store.root / 'actual-catalog.json').read_bytes(), r.encoded([row]))
        self.assertTrue(self.reader(store).validate())

    def test_small_fields_and_appended_copy_remain_unchanged(self):
        store = self.store(threshold=1024); events = r.RecordedEvents(store)
        entry = dict(id=1, label='marker', returncode=3, stdout='A\nB\n', stderr='55000\n')
        before = copy.deepcopy(entry); events.append(entry)
        self.assertEqual(entry, before); self.assertEqual(events[0], before)
        self.assertEqual(store.compact('x' * 2000), store.compact('x' * 2000))

    def test_shared_scopes_exact_aliases_and_mutable_atomic_replacement(self):
        store = self.store(); store.scope('case1'); store.scope('case2')
        rows = [{'actual': 'raw\nα'}]
        pin = store.save('capture.json', rows, scope='case1')
        store.save('capture.json', rows, scope='case2')
        a = store.root / 'case1/capture.json'; b = store.root / 'case2/capture.json'
        self.assertEqual(a.stat().st_ino, b.stat().st_ino)
        self.assertEqual(a.stat().st_nlink, 3)
        self.assertEqual(stat.S_IMODE(a.stat().st_mode), 0o444)
        store.save('commands.json', [{'stdout': 'first'}], scope='case1')
        old_inode = (store.root / 'case1/commands.json').stat().st_ino
        store.save('commands.json', [{'stdout': 'second'}], scope='case1')
        self.assertNotEqual((store.root / 'case1/commands.json').stat().st_ino, old_inode)
        self.assertEqual(r.digest(a.read_bytes()), pin); self.assertEqual(a.read_bytes(), b.read_bytes())
        self.assertLess(store.physical()['uniqueFileInodes'], store.physical()['names'])
        self.assertTrue(self.reader(store).validate())

    def test_immutable_alias_cannot_be_rewritten(self):
        store = self.store(); store.save('capture.json', [1])
        with self.assertRaises(r.EvidenceError): store.save('capture.json', [2])
        self.assertEqual(json.loads((store.root / 'capture.json').read_bytes()), [1])
        self.assertTrue(store.incomplete)

    def test_tamper_missing_blob_index_pin_and_untracked_file(self):
        for attack in ('tamper', 'missing', 'index', 'extra'):
            with self.subTest(attack=attack):
                store = self.store(threshold=1); ref = store.compact('abc' * 100)
                store.save('commands.json', [{'stdout': ref}]); reader = self.reader(store)
                blob = store.root / ref['blob']
                if attack == 'tamper':
                    blob.chmod(0o600); blob.write_bytes(b'changed')
                elif attack == 'missing': blob.unlink()
                elif attack == 'index':
                    (store.root / 'storage-index.json').write_text('{}')
                    with self.assertRaises(r.EvidenceError):
                        r.EvidenceReader(store.root, expected_index_sha256='0' * 64)
                    continue
                else: (store.root / 'untracked.json').write_text('[]')
                with self.assertRaises((r.EvidenceError, FileNotFoundError)): reader.validate()

    def test_gzip_rejects_truncation_trailing_multiple_expansion_utf8(self):
        cases = [gzip.compress(b'abc', mtime=0)[:-1],
                 gzip.compress(b'abc', mtime=0) + b'junk',
                 gzip.compress(b'abc', mtime=0) * 2,
                 gzip.compress(b'A' * 10000, mtime=0),
                 gzip.compress(b'\xff', mtime=0)]
        for number, packed in enumerate(cases):
            store = self.store(threshold=1)
            ref = dict(encoding='gzip-utf8-v1', blob='stdout-' + r.digest(packed) + '.gz',
                       storedSha256=r.digest(packed), storedBytes=len(packed),
                       logicalSha256=r.digest(b'abc' if number < 4 else b'\xff'), logicalBytes=3 if number < 4 else 1)
            # Correct file hashes, names, index pin, and descriptor relationships;
            # the actual gzip/UTF8 decoder must reject the hostile bytes.
            self.assertEqual(store._blob(packed, 'gzip'), ref['blob'])
            store.blobs[ref['blob']]['stdout'] = ref
            store.save('commands.json', [{'stdout': ref}])
            reader = self.reader(store)
            with self.subTest(number=number), self.assertRaises(r.EvidenceError): reader.stdout(ref)

    def test_closed_typed_index_rejects_correctly_pinned_malformed_metadata(self):
        def change_role(index):
            index['files']['capture.json']['role'] = 'invented-role'
        def change_blob(index):
            next(iter(index['blobs'].values()))['kind'] = 'invented-kind'
        def change_reference(index):
            index['files']['commands.json']['stdoutRefs'][0]['logicalBytes'] += 1
        mutations = [
            lambda i: i.update(recordingComplete='false', qualificationAllowed='false'),
            lambda i: i.update(recordingComplete=1, qualificationAllowed=1),
            lambda i: i.update(qualificationAllowed=False),
            lambda i: i.update(unrecognized=True),
            lambda i: i['limits'].update(itemBytes=True),
            lambda i: i['limits'].update(reservedBytes=0),
            lambda i: i['limits'].update(unknownLimit=1),
            lambda i: i['files']['capture.json'].update(bytes=True),
            lambda i: i['files']['capture.json'].update(unrecognized=True),
            lambda i: i['files']['capture.json'].update(blob='missing.json'),
            lambda i: i['blobs'].clear(), change_role, change_blob, change_reference,
            lambda i: i['physical'].update(fileNames=0),
            lambda i: i['physical']['links'][0].update(expectedNlink=True),
            lambda i: i.update(scopes=['../escape']),
            lambda i: i.update(exclusions=['anything']),
            lambda i: i['files']['commands.json'].update(role='alias', blob=next(n for n, v in i['blobs'].items() if v['kind'] == 'json')),
        ]
        for number, mutation in enumerate(mutations):
            with self.subTest(number=number):
                store = self.store(threshold=1)
                store.save('capture.json', [1])
                store.save('commands.json', [{'stdout': store.compact('x' * 100)}])
                store.seal()
                path = store.root / 'storage-index.json'
                value = json.loads(path.read_bytes()); mutation(value)
                path.write_bytes(r.encoded(value))
                with self.assertRaises(r.EvidenceError):
                    reader = r.EvidenceReader(store.root, expected_index_sha256=r.digest(path.read_bytes()))
                    reader.validate()

    def test_declared_smaller_item_bound_applies_to_index_files_refs_and_inline(self):
        store = self.store(max_item=8192, threshold=32)
        ref = store.compact('x' * 1000)
        store.save('capture.json', [1])
        store.save('commands.json', [{'stdout': ref}])
        reader = self.reader(store)
        self.assertTrue(reader.validate())
        with self.assertRaises(r.EvidenceError): reader.stdout('x' * 8193)
        with self.assertRaises(r.EvidenceError): reader.stdout(dict(ref, logicalBytes=8193))
        alias = store.root / 'capture.json'; alias.chmod(0o600)
        alias.write_bytes(b'x' * 8193)
        with self.assertRaises(r.EvidenceError): reader.raw('capture.json')
        for smaller in (1, 128):
            other = self.store(); other.save('capture.json', ['x' * 300])
            other.seal(); path = other.root / 'storage-index.json'
            value = json.loads(path.read_bytes()); value['limits']['itemBytes'] = smaller
            path.write_bytes(r.encoded(value))
            with self.assertRaises(r.EvidenceError):
                r.EvidenceReader(other.root, expected_index_sha256=r.digest(path.read_bytes()))
        other = self.store(max_item=32768, threshold=32)
        other.save('commands.json', [{'stdout': other.compact('x' * 10000)}])
        other.seal(); path = other.root / 'storage-index.json'
        value = json.loads(path.read_bytes()); value['limits']['itemBytes'] = 8192
        path.write_bytes(r.encoded(value))
        self.assertLess(path.stat().st_size, 8192)
        with self.assertRaises(r.EvidenceError):
            r.EvidenceReader(other.root, expected_index_sha256=r.digest(path.read_bytes()))

    def test_duplicate_index_members_and_byte_writer_budget_without_registration(self):
        store = self.store(); store.save('capture.json', [])
        store.seal(); path = store.root / 'storage-index.json'
        raw = path.read_bytes().replace(b'"recordingComplete": true,',
            b'"recordingComplete": true, "recordingComplete": false,')
        path.write_bytes(raw)
        with self.assertRaises(r.EvidenceError):
            r.EvidenceReader(store.root, expected_index_sha256=r.digest(raw))
        outside = self.parent / 'outside.sql'; outside.write_bytes(b'unchanged outside source\n')
        other = self.store()
        with self.assertRaises(r.EvidenceError): other.save_bytes('operator.sql', outside)
        self.assertEqual(outside.read_bytes(), b'unchanged outside source\n')
        budget = self.store(max_bytes=128 * 1024, reserve_bytes=64 * 1024)
        f, calls = self.fixture(budget)
        f.start_attempted = True
        (f.work / 'data/postmaster.pid').write_text('12345\n' + str(f.work / 'data') + '\n0\n55439\n' + str(f.work / 'socket') + '\n\n')
        with self.assertRaises(r.EvidenceError): budget.save_bytes('large.bin', b'x' * 80000)
        self.assertEqual(budget.files, {})
        self.assertTrue(f.cleanup()['completed'])
        self.assertEqual([argv[-1] for argv in calls], ['stop', 'status'])
        self.assertFalse(self.reader(budget).validate())
        healthy = self.store(); healthy.failure_report()
        self.assertTrue(healthy.incomplete)
        self.assertFalse(self.reader(healthy).validate())

    def test_exact_byte_writer_binary_sql_aliases_and_bad_kind_relationships(self):
        store = self.store(); store.scope('case')
        binary = b'\x00\xff\xfe exact\r\n'
        sql = 'SELECT \'α\';\r\n-- exact trailing newline\n'.encode('utf-8')
        self.assertEqual(store.save_bytes('proof.bin', binary), r.digest(binary))
        store.save_bytes('operator.sql', sql)
        store.save_bytes('operator.sql', sql, scope='case')
        first, second = store.root / 'operator.sql', store.root / 'case/operator.sql'
        self.assertEqual(first.read_bytes(), sql)
        self.assertEqual(first.stat().st_ino, second.stat().st_ino)
        self.assertEqual(first.stat().st_nlink, 3)
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o444)
        reader = self.reader(store)
        self.assertTrue(reader.validate())
        self.assertEqual(reader.raw('proof.bin'), binary)
        self.assertEqual(reader.raw('case/operator.sql'), sql)
        with self.assertRaises(r.EvidenceError): reader.read('proof.bin')
        path = store.root / 'storage-index.json'; value = json.loads(path.read_bytes())
        value['files']['operator.sql'].update(role='alias', stdoutRefs=[])
        path.write_bytes(r.encoded(value))
        with self.assertRaises(r.EvidenceError):
            r.EvidenceReader(store.root, expected_index_sha256=r.digest(path.read_bytes()))

    def test_byte_budget_refusal_and_fifth_case_cleanup_tail(self):
        store = self.store(max_item=32768, threshold=1024,
                           max_bytes=512 * 1024, reserve_bytes=128 * 1024)
        for number in range(1, 6):
            scope = 'case' + str(number); f, calls = self.fixture(store, scope)
            f.start_attempted = True
            (f.work / 'data/postmaster.pid').write_text('12345\n' + str(f.work / 'data') + '\n0\n55439\n' + str(f.work / 'socket') + '\n\n')
            if number == 5:
                with self.assertRaises(r.EvidenceError):
                    store.save_bytes('too-large.bin', b'x' * 32769)
            self.assertTrue(f.cleanup()['completed'])
            self.assertEqual([argv[-1] for argv in calls[-2:]], ['stop', 'status'])
        value = json.loads((store.root / 'recording-failure.json').read_bytes())
        self.assertFalse(value['qualificationAllowed'])
        self.assertEqual(len(value['cleanupEvents']), 8)
        self.assertEqual([e['scope'] for e in value['cleanupEvents'][-2:]], ['case5', 'case5'])
        self.assertEqual([e['label'] for e in value['cleanupEvents'][-2:]], ['owned-cluster-stop', 'owned-cluster-status'])
        self.assertFalse(self.reader(store).validate())

    def test_path_escape_symlinks_and_foreign_hardlinks(self):
        store = self.store(); store.save('capture.json', [1])
        for name in ('../escape', '/absolute', 'a/../escape'):
            with self.assertRaises(r.EvidenceError): store._path(name)
        outside = self.parent / 'outside'; outside.write_text('[]')
        (store.root / 'escape.json').symlink_to(outside)
        with self.assertRaises(r.EvidenceError): store._audit()
        (store.root / 'escape.json').unlink()
        os.link(store.root / 'capture.json', self.parent / 'foreign-link')
        with self.assertRaises(r.EvidenceError): store._audit()

    def test_per_blob_and_name_limits(self):
        store = self.store(max_item=1024, threshold=32)
        with self.assertRaises(r.EvidenceError): store.compact('a' * 1025)
        store = self.store(max_names=16)
        with self.assertRaises(r.EvidenceError):
            for index in range(20): store.save('capture-' + str(index) + '.json', [index])
        self.assertTrue(store.incomplete)
        self.assertLessEqual(store.physical()['names'], 16)
        self.assertFalse(self.reader(store).validate())
        events_store = self.store(max_names=16); events = r.RecordedEvents(events_store)
        for number in range(9):
            events.append(dict(id=number, label='small', returncode=0, stdout='', stderr=''))
        self.assertTrue(events_store.incomplete)

    def test_reader_bounds_alias_relationship_and_scope_symlink(self):
        store = self.store(threshold=1); ref = store.compact('α' * 100)
        store.save('capture.json', [1]); store.scope('case1')
        reader = self.reader(store)
        for field in ('logicalBytes', 'storedBytes'):
            for value in (True, -1, r.MAX_ITEM + 1):
                with self.subTest(field=field, value=value), self.assertRaises(r.EvidenceError):
                    reader.stdout(dict(ref, **{field: value}))
        alias = store.root / 'capture.json'; raw = alias.read_bytes()
        alias.unlink(); alias.write_bytes(raw); alias.chmod(0o444)
        with self.assertRaises(r.EvidenceError): reader.validate()
        other = self.store(); other.scope('case')
        path = other.root / 'case'; path.rmdir(); path.symlink_to(self.parent)
        with self.assertRaises(r.EvidenceError): other.save('capture.json', [], scope='case')

    def test_budget_failure_cannot_block_frozen_owned_cleanup(self):
        store = self.store(max_bytes=128 * 1024, reserve_bytes=64 * 1024, threshold=32)
        f, calls = self.fixture(store)
        f.start_attempted = True
        (f.work / 'data/postmaster.pid').write_text('12345\n' + str(f.work / 'data') + '\n0\n55439\n' + str(f.work / 'socket') + '\n\n')
        self.output = 'ok\n'; f.command('first', ['fake'])
        with self.assertRaises(r.EvidenceError): store.save('too-large.json', ['x' * 80000])
        cleanup = f.cleanup()
        self.assertTrue(cleanup['completed'])
        self.assertEqual([argv[-1] for argv in calls[-2:]], ['stop', 'status'])
        self.assertTrue(f.evidence_errors)
        self.assertTrue(store.incomplete)
        failure = json.loads((store.root / 'recording-failure.json').read_bytes())
        self.assertFalse(failure['qualificationAllowed'])
        self.assertEqual([e['label'] for e in failure['cleanupEvents']], ['owned-cluster-stop', 'owned-cluster-status'])
        self.assertFalse(self.reader(store).validate())
        store.save('transition-manifest.json', dict(fullS5Qualified=True,
            boundedSubsetCompleted=True, qualification={'S5': True}))
        manifest = json.loads((store.root / 'transition-manifest.json').read_bytes())
        self.assertFalse(manifest['fullS5Qualified'])
        self.assertFalse(manifest['qualification']['S5'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
