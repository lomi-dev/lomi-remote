"""Read-only exact-closure and collision gate for the supervised runner."""
import hashlib
import json
import os
import sys
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INVENTORY = json.loads((HERE / 'runner-source-inventory.json').read_bytes())
DENIED = []
PATH_MUTATIONS = {
    'os.mkdir', 'os.remove', 'os.rmdir', 'os.rename', 'os.replace', 'os.chmod',
    'os.chown', 'os.symlink', 'os.link', 'os.truncate', 'os.utime', 'os.chflags',
    'os.lchflags', 'os.setxattr', 'os.removexattr', 'os.ftruncate', 'os.fchmod',
    'os.fchown', 'os.fchflags', 'os.write', 'os.pwrite', 'os.writev',
    'os.sendfile', 'os.copy_file_range', 'os.splice',
}


def _audit(event, args):
    if event in PATH_MUTATIONS:
        DENIED.append(event)
        raise AssertionError('runner source inventory gate is read-only')
    if (event.startswith(('socket.', 'subprocess.', 'multiprocessing.')) or
            event in {'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.system',
                      'os.exec', 'os.execve', 'os.spawn', 'os.kill', 'os.killpg',
                      'ctypes.dlopen', 'pty.spawn'}):
        DENIED.append(event)
        raise AssertionError('process or network activity is forbidden')
    if event == 'open':
        path, mode, flags = args
        writing = ((isinstance(mode, str) and any(ch in mode for ch in 'wax+')) or
                   (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR |
                    os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
        if writing:
            DENIED.append('write')
            raise AssertionError('runner source preflight is read-only')


sys.addaudithook(_audit)


class RunnerSourcePreflight(unittest.TestCase):
    def test_exact_recursive_lock_edges_and_internal_conflicts(self):
        self.assertEqual(INVENTORY['status'],
                         'SOURCE_ONLY_DUAL_VIEW_DEPENDENCY_PREFLIGHT_PASSED_RUNTIME_NOT_ADMITTED')
        self.assertEqual(INVENTORY['unresolved'], [])
        locks = INVENTORY['locks']
        lock_map = {row['path']: row for row in locks}
        self.assertEqual(len(lock_map), len(locks))
        entries = INVENTORY['entries']
        entry_map = {row['id']: row for row in entries}
        self.assertEqual(len(entry_map), len(entries))
        self.assertEqual(INVENTORY['counts']['locks'], len(locks))
        self.assertEqual(INVENTORY['counts']['edges'], len(INVENTORY['edges']))
        self.assertEqual(INVENTORY['counts']['uniqueEntries'], len(entries))

        observed = set()
        discovered = {INVENTORY['rootLock']}
        pending = [INVENTORY['rootLock']]
        while pending:
            lock_path = pending.pop()
            lock_row = lock_map[lock_path]
            lock_entry = entry_map[lock_row['entryId']]
            self.assertEqual(lock_entry['logicalPath'], lock_path)
            self.assertEqual(lock_entry['sha256'], lock_row['sha256'])
            raw = self._resolve(lock_entry)
            lock_data = json.loads(raw)
            parent = Path(lock_path).parent
            refs = [('dependency', path, digest)
                    for path, digest in lock_data.get('dependenciesSha256', {}).items()]
            refs += [('local', (parent / name).as_posix(), digest)
                     for name, digest in lock_data.get('localSha256', {}).items()]
            for kind, path, digest in refs:
                matches = [e for e in entries if e['logicalPath'] == path and
                           e['sha256'] == digest]
                self.assertEqual(len(matches), 1, (lock_path, path, digest))
                entry = matches[0]
                self.assertEqual(hashlib.sha256(self._resolve(entry)).hexdigest(), digest)
                observed.add((lock_path, kind, path, digest, entry['id']))
                if path.endswith('inputs.lock.json'):
                    self.assertIn(path, lock_map)
                    if path not in discovered:
                        discovered.add(path)
                        pending.append(path)
        self.assertEqual(discovered, set(lock_map))
        expected = {(edge['fromLock'], edge['kind'], edge['path'], edge['sha256'],
                     edge['toEntry']) for edge in INVENTORY['edges']}
        self.assertEqual(observed, expected)
        self.assertEqual(len(INVENTORY['edges']), 3039)
        self.assertEqual(INVENTORY['actualCTASCasesExecuted'], 0)
        self.assertFalse(INVENTORY['fullS5Qualified'])

        reachable_hashes = {}
        for edge in INVENTORY['edges']:
            reachable_hashes.setdefault(edge['path'], set()).add(edge['sha256'])
        reachable_hashes.setdefault(INVENTORY['rootLock'], set()).add(
            INVENTORY['rootLockSha256'])
        self.assertEqual({p: sorted(hs) for p, hs in reachable_hashes.items()},
                         INVENTORY['pathHashes'])
        collisions = {path: set(hashes) for path, hashes in
                      reachable_hashes.items() if len(hashes) > 1}
        self.assertEqual(collisions, {
            'tests/consumer-fixture-evidence/recording.py': {
                '14312e038a7e1333d6efad810711b585678b9166c86015d7bf56194e7ea57933',
                '320f62eca99763416ab4b9058cf29baec69042bfe77794eebd9364484c169c4f'}})
        boundary = INVENTORY['designBoundary']
        self.assertFalse(boundary['runtimeAdmission'])
        self.assertIn('PASS', boundary['runnerDependenciesPreflight'])
        self.assertIn('PASS', boundary['historicalConstructorLoadAdmitted'])
        self.assertIn('NOT_CALLED', boundary['runtimeMain'])
        self.assertEqual(DENIED, [])

    def _resolve(self, entry):
        for relative in entry['candidates']:
            candidate_rel = Path(relative)
            self.assertFalse(candidate_rel.is_absolute())
            self.assertNotIn('..', candidate_rel.parts)
            candidate = ROOT / candidate_rel
            self.assertFalse(any(part.is_symlink() for part in
                                 (candidate, *candidate.parents)), relative)
            try:
                raw = candidate.read_bytes()
            except OSError:
                continue
            if hashlib.sha256(raw).hexdigest() == entry['sha256']:
                return raw
        self.fail('no exact source candidate for ' + entry['id'])


if __name__ == '__main__':
    unittest.main()
