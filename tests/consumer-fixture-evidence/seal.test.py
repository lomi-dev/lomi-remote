"""Staged seal-only checks plus all 16 inherited pure recorder tests."""
import importlib.util
import os
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('prior_recorder_pure_tests', HERE / 'recording.test.py')
prior = importlib.util.module_from_spec(spec); spec.loader.exec_module(prior)
r = prior.r
WORK_COUNTS = []


class SealTests(prior.RecorderTests):
    def pair(self):
        store = self.store(); store.save('early.json', [1]); store.save('late.json', [2])
        return store

    def mutate(self, store, kind):
        target = store.root / 'early.json'
        if kind in ('same-size', 'metadata'):
            before = target.stat(); raw = target.read_bytes()
            target.chmod(0o600)
            target.write_bytes(raw.replace(b'1', b'9') if kind == 'same-size' else raw)
            target.chmod(0o444)
            os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        elif kind == 'replace':
            temp = store.root / 'replacement.json'
            temp.write_bytes(target.read_bytes()); temp.chmod(0o444)
            os.replace(temp, target)
        elif kind == 'hardlink':
            os.link(target, self.parent / ('unexpected-link-' + store.root.name))
        elif kind == 'untracked':
            (store.root / 'untracked.json').write_text('[]')
        elif kind == 'missing':
            target.unlink()
        elif kind == 'mode':
            target.chmod(0o600)
        elif kind == 'registry':
            store.files['early.json']['sha256'] = '0' * 64
        else:
            raise AssertionError(kind)

    def test_seal_wrong_hash_and_prebatch_namespace_guards(self):
        for kind in ('same-size', 'replace', 'hardlink', 'untracked', 'missing', 'mode', 'registry'):
            with self.subTest(kind=kind):
                store = self.pair(); self.mutate(store, kind)
                with self.assertRaises((r.EvidenceError, OSError)):
                    store.seal()
                self.assertTrue(store.incomplete)

    def test_cross_file_after_earlier_hash_cannot_escape_batch_closure(self):
        for kind in ('same-size', 'metadata', 'replace', 'hardlink', 'untracked', 'missing', 'mode', 'registry'):
            with self.subTest(kind=kind):
                store = self.pair(); original = store._seal_read; reads = []
                def hooked(name, expected):
                    reads.append(name)
                    if name == 'late.json':
                        self.assertIn('early.json', reads)
                        self.mutate(store, kind)
                    return original(name, expected)
                store._seal_read = hooked
                with self.assertRaises((r.EvidenceError, OSError)):
                    store.seal()
                self.assertTrue(store.incomplete)
                self.assertEqual(reads.count('early.json'), 1)
                self.assertNotIn('storage-index.json', reads)

    def test_index_publication_cannot_hide_prior_file_or_registry_mutation(self):
        for kind in ('same-size', 'metadata', 'replace', 'hardlink', 'untracked', 'missing', 'registry'):
            with self.subTest(kind=kind):
                store = self.pair(); original = store._publish
                def hooked(name, *args, **kwargs):
                    result = original(name, *args, **kwargs)
                    if name == 'storage-index.json':
                        self.mutate(store, kind)
                    return result
                store._publish = hooked
                with self.assertRaises((r.EvidenceError, OSError)):
                    store.seal()
                self.assertTrue(store.incomplete)

    def test_published_index_bytes_and_registration_are_verified(self):
        for kind in ('bytes', 'registration', 'mode'):
            with self.subTest(kind=kind):
                store = self.pair(); original = store._publish
                def hooked(name, *args, **kwargs):
                    result = original(name, *args, **kwargs)
                    if name == 'storage-index.json':
                        if kind == 'bytes':
                            path = store.root / name; raw = path.read_bytes()
                            path.write_bytes(raw.replace(b'consumer', b'Consumer', 1))
                        elif kind == 'registration':
                            store.files[name]['sha256'] = '0' * 64
                        else:
                            (store.root / name).chmod(0o444)
                    return result
                store._publish = hooked
                with self.assertRaises(r.EvidenceError): store.seal()
                self.assertTrue(store.incomplete)

    def test_index_publication_failure_keeps_frozen_fake_cleanup_independent(self):
        store = self.store(); f, calls = self.fixture(store)
        f.start_attempted = True
        (f.work / 'data/postmaster.pid').write_text('12345\n' + str(f.work / 'data') + '\n0\n55439\n' + str(f.work / 'socket') + '\n\n')
        self.output = 'actual\n'; f.command('before-seal', ['fake'])
        original = store._publish
        def failed_index(name, *args, **kwargs):
            if name == 'storage-index.json':
                raise OSError('injected new-index publication failure')
            return original(name, *args, **kwargs)
        store._publish = failed_index
        with self.assertRaises(OSError): store.seal()
        self.assertTrue(store.incomplete)
        self.assertTrue(f.cleanup()['completed'])
        self.assertEqual([argv[-1] for argv in calls[-2:]], ['stop', 'status'])
        self.assertTrue(f.evidence_errors)
        self.assertFalse(r.strict_json((store.root / 'recording-failure.json').read_bytes())['qualificationAllowed'])

    def test_mutation_after_final_index_hash_is_caught_by_final_closure(self):
        for kind in ('prior-file', 'index-file', 'index-registration'):
            with self.subTest(kind=kind):
                store = self.pair(); original = store._seal_read
                def hooked(name, expected):
                    result = original(name, expected)
                    if name == 'storage-index.json':
                        if kind == 'prior-file':
                            self.mutate(store, 'same-size')
                        elif kind == 'index-file':
                            path = store.root / name
                            path.write_bytes(path.read_bytes())
                        else:
                            store.files[name]['sha256'] = '0' * 64
                    return result
                store._seal_read = hooked
                with self.assertRaises(r.EvidenceError): store.seal()
                self.assertTrue(store.incomplete)

    def test_repeated_valid_seal_keeps_valid_records_and_new_index(self):
        store = self.pair()
        first = store.seal()
        reader = r.EvidenceReader(store.root, expected_index_sha256=first['storage-index.json'])
        self.assertTrue(reader.validate())
        retained = {name: (pin, (store.root / name).read_bytes())
                    for name, pin in first.items() if name != 'storage-index.json'}
        second = store.seal()
        self.assertEqual(set(first), set(second))
        self.assertFalse(store.incomplete)
        reader = r.EvidenceReader(store.root, expected_index_sha256=second['storage-index.json'])
        self.assertTrue(reader.validate())
        self.assertEqual(reader.read('early.json'), [1])
        self.assertEqual(reader.read('late.json'), [2])
        for name, (pin, raw) in retained.items():
            self.assertEqual(second[name], pin)
            self.assertEqual((store.root / name).read_bytes(), raw)

    def test_in_read_same_size_change_with_restored_mtime_rejects_ctime(self):
        store = self.pair(); target = store.root / 'early.json'
        before = target.stat(); original_read = r.os.read; triggered = []
        def mutate_during_read(fd, limit):
            raw = original_read(fd, limit)
            current = os.fstat(fd)
            if raw and not triggered and (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino):
                triggered.append(True)
                self.mutate(store, 'same-size')
                self.assertEqual(target.stat().st_mtime_ns, before.st_mtime_ns)
                self.assertNotEqual(target.stat().st_ctime_ns, before.st_ctime_ns)
            return raw
        r.os.read = mutate_during_read
        try:
            with self.assertRaisesRegex(r.EvidenceError, 'seal file changed during read'):
                store.seal()
        finally:
            r.os.read = original_read
        self.assertEqual(triggered, [True])
        self.assertTrue(store.incomplete)

    def synthetic(self, count):
        """Trusted synthetic already-recorded namespace, avoiding quadratic setup."""
        store = self.store(); raw = r.encoded([1]); blob = store._blob(raw, 'json')
        for number in range(count - 1):
            name = 'capture-' + str(number) + '.json'
            os.link(store.root / blob, store.root / name)
            store._remember(name, raw, 'alias')
            store.files[name].update(blob=blob, stdoutRefs=[])
        store._audit()
        self.assertEqual(len(store.files), count)
        return store

    def test_constant_full_audits_and_one_hash_per_file_for_1000_names(self):
        audit_counts = []
        for count in (4, 1000):
            with self.subTest(count=count):
                store = self.synthetic(count); audit = store._audit; read = store._seal_read
                counts = {'audits': 0}; reads = []
                def counted_audit():
                    counts['audits'] += 1
                    return audit()
                def counted_read(name, expected):
                    reads.append(name)
                    return read(name, expected)
                def forbidden_verify(name):
                    raise AssertionError('seal must not call globally-audited _verify per file')
                store._audit = counted_audit; store._seal_read = counted_read
                store._verify = forbidden_verify
                hashes = store.seal()
                self.assertEqual(len(reads), count + 1)
                self.assertEqual(len(set(reads)), count + 1)
                self.assertEqual(set(hashes), set(reads))
                for name, pin in hashes.items():
                    self.assertEqual(pin, r.digest((store.root / name).read_bytes()))
                audit_counts.append(counts['audits'])
                WORK_COUNTS.append(dict(inputNames=count, fullAudits=counts['audits'],
                                        boundedReads=len(reads), uniqueReadNames=len(set(reads))))
                self.assertLessEqual(counts['audits'], 8)
                reader = r.EvidenceReader(store.root, expected_index_sha256=hashes['storage-index.json'])
                self.assertTrue(reader.validate())
        self.assertEqual(audit_counts[0], audit_counts[1])


if __name__ == '__main__':
    try:
        unittest.main(verbosity=2)
    finally:
        print('SEAL_WORK_COUNTS ' + r.json.dumps(WORK_COUNTS, sort_keys=True))
