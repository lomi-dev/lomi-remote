"""No-child verification of the recursively pinned CTAS source graph."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import unittest
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DENIED = []
ALLOWED_WRITE_ROOTS = set()
PROCESS_EVENTS = {
    'subprocess.Popen', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.system',
    'os.exec', 'os.execve', 'os.spawn', 'os.kill', 'os.killpg', 'ctypes.dlopen',
    'pty.spawn', 'multiprocessing.Process.start',
}
PROCESS_EVENT_PREFIXES = ('socket.', 'subprocess.', 'multiprocessing.')
PATH_MUTATION_EVENTS = {
    'os.mkdir', 'os.remove', 'os.rmdir', 'os.rename', 'os.replace', 'os.chmod',
    'os.chown', 'os.symlink', 'os.link', 'os.truncate', 'os.utime', 'os.chflags',
    'os.lchflags', 'os.setxattr', 'os.removexattr',
}
UNSCOPED_MUTATION_EVENTS = {
    'os.ftruncate', 'os.fchmod', 'os.fchown', 'os.fchflags', 'os.write',
    'os.pwrite', 'os.writev', 'os.sendfile', 'os.copy_file_range', 'os.splice',
}


def _within_allowed_root(value):
    if not isinstance(value, (str, bytes, os.PathLike)):
        return False
    candidate = Path(os.path.abspath(os.fsdecode(value)))
    for path in (candidate, *candidate.parents):
        if path.is_symlink():
            return False
    if candidate.resolve(strict=False) != candidate:
        return False
    for allowed in ALLOWED_WRITE_ROOTS:
        allowed = Path(os.path.abspath(allowed))
        if any(path.is_symlink() for path in (allowed, *allowed.parents)):
            continue
        if allowed.resolve(strict=False) != allowed:
            continue
        try:
            candidate.relative_to(allowed)
            return True
        except ValueError:
            pass
    return False


def audit(event, args):
    if event in PROCESS_EVENTS or event in UNSCOPED_MUTATION_EVENTS or event.startswith(PROCESS_EVENT_PREFIXES):
        DENIED.append(event)
        raise AssertionError('process, network, or unscoped mutation event forbidden')
    if event == 'open':
        path, mode, flags = args
        writing = (isinstance(mode, str) and any(ch in mode for ch in 'wax+')) or (
            isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        if writing and not _within_allowed_root(path):
            DENIED.append('unexpected-write:open')
            raise AssertionError('write outside the unique temporary materialization root')
    elif event in PATH_MUTATION_EVENTS:
        if event in ('os.rename', 'os.replace', 'os.link'):
            destinations = args[:2]
        elif event == 'os.symlink':
            destinations = args[1:2]
        else:
            destinations = args[:1]
        exact_allowed_symlink_cleanup = False
        if event == 'os.remove' and destinations and Path(destinations[0]).is_symlink():
            leaf = Path(destinations[0])
            exact_allowed_symlink_cleanup = leaf in ALLOWED_WRITE_ROOTS
            destinations = (leaf.parent,)
        if not exact_allowed_symlink_cleanup and (
                not destinations or not all(_within_allowed_root(path) for path in destinations)):
            DENIED.append('unexpected-write:' + event)
            raise AssertionError('filesystem mutation outside the unique temporary root')


def unique_temp_root():
    path = HERE / ('.ctas-successor-test-' + uuid.uuid4().hex)
    ALLOWED_WRITE_ROOTS.add(path)
    try:
        path.mkdir(mode=0o700)
    except BaseException:
        ALLOWED_WRITE_ROOTS.discard(path)
        raise
    return path


def unique_materialization_root():
    path = HERE / ('.ctas-successor-view-' + uuid.uuid4().hex)
    ALLOWED_WRITE_ROOTS.add(path)
    return path


def cleanup_temp_root(path):
    path = Path(path)
    if path.parent != HERE or not path.name.startswith(('.ctas-successor-test-', '.ctas-successor-view-')):
        raise ValueError("cleanup target is not this test's unique package-local root")
    try:
        root_stat = path.lstat()
    except FileNotFoundError:
        ALLOWED_WRITE_ROOTS.discard(path)
        return
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError('cleanup root must be a real directory, not a symlink')

    def remove_tree(directory):
        for child in directory.iterdir():
            child_stat = child.lstat()
            if stat.S_ISLNK(child_stat.st_mode):
                child.unlink()
            elif stat.S_ISDIR(child_stat.st_mode):
                remove_tree(child)
            else:
                child.unlink()
        directory.rmdir()
    try:
        remove_tree(path)
    finally:
        ALLOWED_WRITE_ROOTS.discard(path)


sys.addaudithook(audit)
_spec = importlib.util.spec_from_file_location('ctas_successor_resolver', HERE / 'resolve.py')
resolver = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = resolver
_spec.loader.exec_module(resolver)
INVENTORY = resolver.INVENTORY
ENTRIES = {entry['id']: entry for entry in INVENTORY['entries']}
LOCKS = {lock['path']: lock for lock in INVENTORY['locks']}
EDGES = INVENTORY['closureEdges']


class SuccessorInventory(unittest.TestCase):
    def test_recursive_lock_graph_exact_edges_and_counts(self):
        self.assertEqual(INVENTORY['status'], 'SOURCE_ONLY_RECURSIVE_CLOSURE_NOT_ADMITTED')
        self.assertEqual(INVENTORY['unresolved'], [])
        self.assertEqual(INVENTORY['counts']['locks'], 8)
        lock_paths = [record['path'] for record in INVENTORY['locks']]
        self.assertEqual(len(lock_paths), len(set(lock_paths)), 'duplicate lock paths must fail')
        self.assertEqual(len(LOCKS), len(INVENTORY['locks']))
        self.assertEqual(INVENTORY['counts']['closureEdges'], len(EDGES))
        self.assertEqual(INVENTORY['counts']['uniqueSourceEntries'], len(ENTRIES))
        self.assertEqual(INVENTORY['counts']['proofManifests'], len(INVENTORY['proofManifests']))
        self.assertEqual(len(ENTRIES), len(INVENTORY['entries']))
        edge_keys = [(edge['fromLock'], edge['path'], edge['sha256'], edge['kind']) for edge in EDGES]
        self.assertEqual(len(edge_keys), len(set(edge_keys)), 'duplicate lock edges must fail')
        edge_hashes = {}
        for edge in EDGES:
            edge_hashes.setdefault(edge['path'], set()).add(edge['sha256'])
        self.assertFalse({path: hashes for path, hashes in edge_hashes.items() if len(hashes) > 1})
        path_hashes = {}
        for entry in INVENTORY['entries']:
            path_hashes.setdefault(entry['logicalPath'], set()).add(entry['sha256'])
        collisions = {path: hashes for path, hashes in path_hashes.items() if len(hashes) > 1}
        self.assertEqual(collisions, {'tests/consumer-derivatives-v2-sealing/construct.py': {
            '7edfc912fbc079812ac2e35ace9cd2d56505d12c4ffd7f399e22be676759a3fd',
            'b9ec75b1b593ce9ef94c72706e66ca10a847efac49a79c749424496eee19cf7c'}})

        expected_edges = set()
        discovered_locks = {INVENTORY['rootLock']}
        pending = [INVENTORY['rootLock']]
        for path in pending:
            record = LOCKS[path]
            payload, provenance = resolver.resolve(record['entryId'])
            self.assertIn(provenance, ENTRIES[record['entryId']]['candidates'])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), record['sha256'])
            lock = json.loads(payload)
            parent = Path(path).parent
            items = [('dependency', name, digest)
                     for name, digest in lock.get('dependenciesSha256', {}).items()]
            items += [('local', (parent / name).as_posix(), digest)
                      for name, digest in lock.get('localSha256', {}).items()]
            for kind, logical, digest in items:
                found = next((entry for entry in INVENTORY['entries']
                              if entry['logicalPath'] == logical
                              and entry['sha256'] == digest), None)
                self.assertIsNotNone(found, (path, logical, digest))
                data, candidate = resolver.resolve(found['id'])
                self.assertEqual(candidate, next(c for c in found['candidates']
                                                  if hashlib.sha256((ROOT / c).read_bytes()).hexdigest() == digest))
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                expected_edges.add((path, found['id'], logical, digest, kind))
                if logical.endswith('inputs.lock.json'):
                    self.assertIn(logical, LOCKS)
                    if logical not in discovered_locks:
                        discovered_locks.add(logical)
                        pending.append(logical)
        observed_edges = {(edge['fromLock'], edge['toEntry'], edge['path'],
                           edge['sha256'], edge['kind']) for edge in EDGES}
        self.assertEqual(observed_edges, expected_edges)
        self.assertEqual(discovered_locks, set(LOCKS))
        self.assertEqual(len(EDGES), 2466)

    def test_required_historical_chain_and_proof_manifests(self):
        required = (
            'tests/consumer-derivatives-v2-s5-pre012-extended/inputs.lock.json',
            'tests/consumer-derivatives-v2-s5-pre012/inputs.lock.json',
            'tests/consumer-derivatives-v2-s5-operator-faults/inputs.lock.json',
            'tests/consumer-derivatives-v2-s5-owner-faults/inputs.lock.json',
            'artifacts/consumer-derivatives-v2-s5-owner-faults-preparation/2099a332-2019-4d90-9bbd-84fdf864843b/qualification-source/inputs.lock.json',
            'tests/consumer-derivatives-v2-sealing/inputs.lock.json',
        )
        self.assertTrue(set(required).issubset(LOCKS))
        transitions = (
            ('tests/consumer-derivatives-v2-s5-pre012-ctas/inputs.lock.json',
             'tests/consumer-derivatives-v2-s5-pre012-extended/inputs.lock.json'),
            ('tests/consumer-derivatives-v2-s5-pre012-extended/inputs.lock.json',
             'tests/consumer-derivatives-v2-s5-pre012/inputs.lock.json'),
            ('tests/consumer-derivatives-v2-s5-pre012/inputs.lock.json',
             'tests/consumer-derivatives-v2-s5-operator-faults/inputs.lock.json'),
            ('tests/consumer-derivatives-v2-s5-operator-faults/inputs.lock.json',
             'tests/consumer-derivatives-v2-s5-owner-faults/inputs.lock.json'),
            ('tests/consumer-derivatives-v2-s5-owner-faults/inputs.lock.json',
             'tests/consumer-derivatives-v2-sealing/inputs.lock.json'),
            ('artifacts/consumer-derivatives-v2-s5-owner-faults-preparation/2099a332-2019-4d90-9bbd-84fdf864843b/qualification-source/inputs.lock.json',
             'artifacts/consumer-derivatives-v2-sealing-preparation/d1fb0ffc-4d09-4e1b-b0f0-cae7aecb9546/qualification-source/inputs.lock.json'),
        )
        for left, right in transitions:
            self.assertTrue(any(edge['fromLock'] == left and edge['path'] == right
                                for edge in EDGES), (left, right))
        self.assertEqual(INVENTORY['counts']['sourceManifestEdges'],
                         len(INVENTORY['sourceManifestEdges']))
        self.assertEqual(len(INVENTORY['sourceManifestEdges']), 215)
        manifest_edges = INVENTORY['sourceManifestEdges']
        self.assertEqual(len({(e['manifestPath'], e['sourcePath']) for e in manifest_edges}),
                         len(manifest_edges), 'duplicate source-manifest edges must fail')
        manifest_hashes = {}
        for edge in manifest_edges:
            manifest_hashes.setdefault((edge['manifestPath'], edge['sourcePath']), set()).add(edge['sourceSha256'])
        self.assertFalse({key: values for key, values in manifest_hashes.items() if len(values) > 1})
        by_id = ENTRIES
        proof_by_path = {proof['path']: proof for proof in INVENTORY['proofManifests']}
        self.assertEqual(len(proof_by_path), len(INVENTORY['proofManifests']))
        for edge in manifest_edges:
            proof = proof_by_path.get(edge['manifestPath'])
            self.assertIsNotNone(proof, edge['manifestPath'])
            self.assertEqual(edge['manifestSha256'], proof['sha256'])
            self.assertEqual(edge['manifestEntryId'], proof['entryId'])
            expected_field = ('inputsSha256' if edge['manifestPath'].endswith('source-freeze.json')
                              else 'freeze-sha256.json')
            self.assertEqual(edge['field'], expected_field)

        for proof in INVENTORY['proofManifests']:
            payload, provenance = resolver.resolve(proof['entryId'])
            self.assertIn(provenance, by_id[proof['entryId']]['candidates'])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), proof['sha256'])
            manifest = json.loads(payload)
            edges = [edge for edge in manifest_edges if edge['manifestPath'] == proof['path']]
            if 'inputsSha256' in manifest:
                expected = manifest['inputsSha256']
            elif proof['path'].endswith('freeze-sha256.json'):
                prefix = proof['path'].rsplit('/', 1)[0] + '/'
                expected = {prefix + name: digest for name, digest in manifest.items()}
            else:
                expected = {}
            observed = {edge['sourcePath']: edge['sourceSha256'] for edge in edges}
            self.assertEqual(observed, expected, proof['path'])
            for edge in edges:
                source_entry = by_id[edge['sourceEntryId']]
                self.assertEqual(source_entry['logicalPath'], edge['sourcePath'])
                self.assertEqual(source_entry['sha256'], edge['sourceSha256'])
                self.assertEqual(source_entry['id'], edge['sourceEntryId'])
                data, candidate = resolver.resolve(edge['sourceEntryId'])
                self.assertIn(candidate, edge['candidates'])
                self.assertEqual(hashlib.sha256(data).hexdigest(), edge['sourceSha256'])

        binding = INVENTORY['proofRootBinding']
        lock_record = LOCKS[binding['rootLock']]
        root_lock_payload, _ = resolver.resolve(lock_record['entryId'])
        self.assertEqual(hashlib.sha256(root_lock_payload).hexdigest(), binding['rootLockSha256'])
        self.assertEqual(lock_record['sha256'], binding['rootLockSha256'])
        root_lock = json.loads(root_lock_payload)

        proof_records = {proof['path']: proof for proof in INVENTORY['proofManifests']}
        self.assertEqual(len(proof_records), len(INVENTORY['proofManifests']))
        for path_key, hash_key in (
                ('sourceFreeze', 'sourceFreezeSha256'),
                ('ctasPreparation', 'ctasPreparationSha256'),
                ('outerPreparation', 'outerPreparationSha256')):
            proof_path = binding[path_key]
            proof_record = proof_records.get(proof_path)
            self.assertIsNotNone(proof_record, proof_path)
            self.assertEqual(proof_record['sha256'], binding[hash_key])
            payload, provenance = resolver.resolve(proof_record['entryId'])
            self.assertIn(provenance, ENTRIES[proof_record['entryId']]['candidates'])
            self.assertEqual(hashlib.sha256(payload).hexdigest(), binding[hash_key])
            self.assertEqual(ENTRIES[proof_record['entryId']]['sha256'], binding[hash_key])

        source_freeze = json.loads((ROOT / binding['sourceFreeze']).read_bytes())
        self.assertFalse(source_freeze['fullS5Qualified'])
        self.assertEqual(source_freeze['inputsSha256'][binding['sourceFreezeBindsRootLockPath']],
                         binding['sourceFreezeBindsRootLockSha256'])
        self.assertEqual(binding['sourceFreezeBindsRootLockSha256'], binding['rootLockSha256'])
        ctas_preparation = json.loads((ROOT / binding['ctasPreparation']).read_bytes())
        self.assertEqual(ctas_preparation['sourceFreezeSha256'], binding['sourceFreezeSha256'])
        outer_preparation = json.loads((ROOT / binding['outerPreparation']).read_bytes())
        self.assertEqual(outer_preparation['ctasPreparation']['path'], binding['ctasPreparation'])
        self.assertEqual(outer_preparation['ctasPreparation']['sha256'], binding['ctasPreparationSha256'])

    def test_historic_and_current_construct_are_separate_pins(self):
        historic = next(entry for entry in INVENTORY['entries']
                        if entry['logicalPath'] == 'tests/consumer-derivatives-v2-sealing/construct.py'
                        and entry['sha256'].startswith('7edfc912'))
        current = ENTRIES['current-construct-b9ec']
        self.assertEqual(historic['sha256'],
                         '7edfc912fbc079812ac2e35ace9cd2d56505d12c4ffd7f399e22be676759a3fd')
        self.assertEqual(current['sha256'],
                         'b9ec75b1b593ce9ef94c72706e66ca10a847efac49a79c749424496eee19cf7c')
        self.assertNotEqual(historic['sha256'], current['sha256'])
        old_bytes, old_source = resolver.resolve(historic['id'])
        current_bytes, current_source = resolver.resolve(current['id'])
        self.assertNotEqual(old_bytes, current_bytes)
        self.assertTrue(old_source.startswith(INVENTORY['immutableSnapshots'][0] + '/'))
        self.assertEqual(current_source, 'tests/consumer-derivatives-v2-sealing/construct.py')
        freeze = json.loads((ROOT / INVENTORY['proofManifests'][0]['path']).read_bytes())
        frozen_copy = INVENTORY['immutableSnapshots'][0] + '/tests/consumer-derivatives-v2-sealing/construct.py'
        self.assertEqual(freeze['inputsSha256'][frozen_copy], historic['sha256'])

    def test_materialized_historical_tree_runs_only_dependencies(self):
        mat_spec = importlib.util.spec_from_file_location('ctas_successor_materializer', HERE / 'materialize.py')
        materializer = importlib.util.module_from_spec(mat_spec)
        sys.modules[mat_spec.name] = materializer
        mat_spec.loader.exec_module(materializer)
        view = unique_materialization_root()
        try:
            report = materializer.materialize(view)
            historic_path = view / 'tests/consumer-derivatives-v2-s5-pre012-extended/s5.py'
            historic_entry = next(entry for entry in INVENTORY['entries']
                                  if entry['logicalPath'] == 'tests/consumer-derivatives-v2-s5-pre012-extended/s5.py')
            self.assertEqual(hashlib.sha256(historic_path.read_bytes()).hexdigest(), historic_entry['sha256'])
            construct_path = view / 'tests/consumer-derivatives-v2-sealing/construct.py'
            self.assertEqual(hashlib.sha256(construct_path.read_bytes()).hexdigest(),
                             '7edfc912fbc079812ac2e35ace9cd2d56505d12c4ffd7f399e22be676759a3fd')
            successor_construct = view / 'successor-inputs/tests/consumer-derivatives-v2-sealing/construct.py'
            self.assertEqual(hashlib.sha256(successor_construct.read_bytes()).hexdigest(),
                             'b9ec75b1b593ce9ef94c72706e66ca10a847efac49a79c749424496eee19cf7c')
            self.assertEqual(report['fullS5Qualified'], False)
            self.assertEqual(stat.S_IMODE(view.stat().st_mode), 0o700)
            for path in view.rglob('*'):
                if path.is_file():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o222, 0, str(path))
                elif path.is_dir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700, str(path))
            spec = importlib.util.spec_from_file_location('historical_pre012_extended_s5', historic_path)
            historical_s5 = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = historical_s5
            spec.loader.exec_module(historical_s5)
            lock = historical_s5.dependencies()
            self.assertEqual(lock['fullS5Qualified'], False)
            self.assertEqual(DENIED, [])

        finally:
            cleanup_temp_root(view)

    def test_materializer_rejects_traversal_symlinks_and_collisions(self):
        mat_spec = importlib.util.spec_from_file_location('ctas_successor_materializer_guards', HERE / 'materialize.py')
        materializer = importlib.util.module_from_spec(mat_spec)
        sys.modules[mat_spec.name] = materializer
        mat_spec.loader.exec_module(materializer)
        with self.assertRaises(ValueError):
            materializer._safe_relative('../escape')
        temporary = unique_temp_root()
        try:
            root = temporary
            target = root / 'real-target'
            target.mkdir(mode=0o700)
            link = root / 'linked-view'
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                materializer.materialize(link)
            outside_destination = ROOT / ('.ctas-successor-view-' + uuid.uuid4().hex)
            with self.assertRaisesRegex(ValueError, 'direct child'):
                materializer.materialize(outside_destination)
            with self.assertRaisesRegex(ValueError, 'UUID-named direct child'):
                materializer.materialize(HERE / 'not-a-uuid-view')

            original_edges = materializer.INVENTORY['closureEdges']
            try:
                injected = copy.deepcopy(original_edges[0])
                injected['sha256'] = '0' * 64
                injected['toEntry'] = 'not-a-real-entry'
                injected['kind'] = 'collision-test'
                materializer.INVENTORY['closureEdges'] = original_edges + [injected]
                with self.assertRaisesRegex(ValueError, 'path collision'):
                    materializer.materialize(root / 'collision-view')
            finally:
                materializer.INVENTORY['closureEdges'] = original_edges

            try:
                injected = copy.deepcopy(original_edges[0])
                injected['path'] = '../escape'
                injected['kind'] = 'traversal-test'
                materializer.INVENTORY['closureEdges'] = original_edges + [injected]
                with self.assertRaisesRegex(ValueError, 'unsafe inventory path'):
                    materializer.materialize(root / 'traversal-view')
            finally:
                materializer.INVENTORY['closureEdges'] = original_edges

            outside_alias = root / 'allowed-root-symlink'
            outside_alias.symlink_to(ROOT, target_is_directory=True)
            ALLOWED_WRITE_ROOTS.add(outside_alias)
            probe = outside_alias / ('must-not-write-' + uuid.uuid4().hex)
            with self.assertRaisesRegex(AssertionError, 'write outside'):
                probe.write_text('denied')
            self.assertEqual(DENIED, ['unexpected-write:open'])
            DENIED.clear()
            with self.assertRaisesRegex(AssertionError, 'process, network'):
                audit('socket.any_future_api', ())
            with self.assertRaisesRegex(AssertionError, 'process, network'):
                audit('os.execve', ())
            with self.assertRaisesRegex(AssertionError, 'process, network'):
                audit('os.ftruncate', ())
            with self.assertRaisesRegex(AssertionError, 'filesystem mutation'):
                audit('os.utime', (ROOT / ('must-not-touch-' + uuid.uuid4().hex), None, None))
            with self.assertRaisesRegex(AssertionError, 'filesystem mutation'):
                audit('os.rename', (ROOT / 'outside-source', root / 'inside-destination'))
            with self.assertRaisesRegex(AssertionError, 'filesystem mutation'):
                audit('os.link', (ROOT / 'outside-inode', root / 'inside-hardlink'))
            self.assertEqual(DENIED, ['socket.any_future_api', 'os.execve', 'os.ftruncate',
                                     'unexpected-write:os.utime', 'unexpected-write:os.rename',
                                     'unexpected-write:os.link'])
            DENIED.clear()
            self.assertFalse((ROOT / probe.name).exists())
            ALLOWED_WRITE_ROOTS.remove(outside_alias)

            symlink_root = HERE / ('.ctas-successor-test-' + uuid.uuid4().hex)
            ALLOWED_WRITE_ROOTS.add(symlink_root)
            symlink_root.symlink_to(ROOT, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'real directory, not a symlink'):
                cleanup_temp_root(symlink_root)
            symlink_root.unlink()
            ALLOWED_WRITE_ROOTS.discard(symlink_root)
        finally:
            cleanup_temp_root(temporary)
        self.assertEqual(DENIED, [])

    def test_source_only_status_and_no_runtime_entrypoint(self):
        self.assertFalse(INVENTORY['fullS5Qualified'])
        self.assertEqual(INVENTORY['actualCTASCasesExecuted'], 0)
        self.assertEqual(INVENTORY['unresolved'], [])
        for name in ('resolve.py', 'materialize.py', 'successor.test.py'):
            ast.parse((HERE / name).read_bytes())
        self.assertEqual(DENIED, [])


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(SuccessorInventory))
    print(json.dumps(dict(testsRun=result.testsRun, successful=result.wasSuccessful(),
                          deniedAuditEvents=DENIED, blockedProcessEvents=sorted(PROCESS_EVENTS),
                          blockedProcessPrefixes=list(PROCESS_EVENT_PREFIXES),
                          blockedUnscopedMutationEvents=sorted(UNSCOPED_MUTATION_EVENTS),
                          pathMutationEvents=sorted(PATH_MUTATION_EVENTS),
                          filesystemWriteScope='unique temporary package root only', actualCTASCasesExecuted=0,
                          locks=INVENTORY['counts']['locks'],
                          closureEdges=INVENTORY['counts']['closureEdges'],
                          sourceManifestEdges=INVENTORY['counts']['sourceManifestEdges'],
                          unresolved=len(INVENTORY['unresolved']), fullS5Qualified=False)))
    raise SystemExit(0 if result.wasSuccessful() and not DENIED else 1)
