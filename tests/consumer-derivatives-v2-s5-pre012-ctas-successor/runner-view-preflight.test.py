"""No-child dependency preflight for separate runner and historical views."""
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
ALLOWED = set()
DENIED = []
PROCESS_NAMES = {'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.system', 'os.exec',
                 'os.execve', 'os.spawn', 'os.kill', 'os.killpg', 'ctypes.dlopen',
                 'pty.spawn', 'multiprocessing.Process.start'}
PROCESS_PREFIXES = ('socket.', 'subprocess.', 'multiprocessing.')
MUTATIONS = {'os.mkdir', 'os.remove', 'os.rmdir', 'os.rename', 'os.replace',
             'os.chmod', 'os.chown', 'os.symlink', 'os.link', 'os.truncate',
             'os.utime', 'os.chflags', 'os.lchflags', 'os.setxattr',
             'os.removexattr'}
UNSCOPED = {'os.ftruncate', 'os.fchmod', 'os.fchown', 'os.fchflags', 'os.write',
            'os.pwrite', 'os.writev', 'os.sendfile', 'os.copy_file_range', 'os.splice'}


def _inside(path):
    if not isinstance(path, (str, bytes, os.PathLike)):
        return False
    candidate = Path(os.path.abspath(os.fsdecode(path)))
    if any(part.is_symlink() for part in (candidate, *candidate.parents)):
        return False
    if candidate.resolve(strict=False) != candidate:
        return False
    for root in ALLOWED:
        root = Path(os.path.abspath(root))
        if any(part.is_symlink() for part in (root, *root.parents)):
            continue
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            pass
    return False


def audit(event, args):
    if event in PROCESS_NAMES or event in UNSCOPED or event.startswith(PROCESS_PREFIXES):
        DENIED.append(event)
        raise AssertionError('process or network event forbidden')
    if event == 'open':
        path, mode, flags = args
        writing = ((isinstance(mode, str) and any(ch in mode for ch in 'wax+')) or
                   (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR |
                    os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
        if writing and not _inside(path):
            DENIED.append('open-write')
            raise AssertionError('write outside temporary views')
    elif event in MUTATIONS:
        paths = args[:2] if event in ('os.rename', 'os.replace', 'os.link') else (
            args[1:2] if event == 'os.symlink' else args[:1])
        if not paths or not all(_inside(p) for p in paths):
            DENIED.append(event)
            raise AssertionError('filesystem mutation outside temporary views')


sys.addaudithook(audit)


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _new_view(prefix):
    path = HERE / (prefix + uuid.uuid4().hex)
    ALLOWED.add(path)
    return path


def _clean(path):
    path = Path(path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError('view cleanup root must be a real directory')
    def remove(directory):
        for child in directory.iterdir():
            mode = child.lstat().st_mode
            if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
                remove(child)
            else:
                child.unlink()
        directory.rmdir()
    try:
        remove(path)
    finally:
        ALLOWED.discard(path)


def _supplement_constructor_inputs(view):
    """Materialize exact inputs named by the constructor and its pinned S0-S4 driver."""
    import hashlib

    def add(relative, digest):
        rel = Path(relative)
        if rel.is_absolute() or '..' in rel.parts or not rel.parts:
            raise ValueError('unsafe historical constructor evidence path')
        target = view / rel
        if target.exists():
            payload = target.read_bytes()
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError('historical view evidence path collision: ' + relative)
            return
        source = ROOT / rel
        if any(part.is_symlink() for part in (source, *source.parents)):
            raise ValueError('symlink in historical evidence candidate: ' + relative)
        payload = source.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError('historical evidence candidate hash mismatch: ' + relative)
        parent = target.parent
        missing = []
        while parent != view and not parent.exists():
            missing.append(parent)
            parent = parent.parent
        if parent != view and not parent.resolve().is_relative_to(view):
            raise ValueError('historical evidence destination escaped view')
        for directory in reversed(missing):
            if directory.is_symlink():
                raise ValueError('symlink in historical evidence destination')
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
        with target.open('xb') as stream:
            stream.write(payload)
        target.chmod(0o444)

    constructor_lock_path = view / 'tests/consumer-derivatives-v2-sealing/inputs.lock.json'
    constructor_lock_raw = constructor_lock_path.read_bytes()
    constructor_lock = json.loads(constructor_lock_raw)
    expected_lock_sha = 'd2b246e4c681688c31a3339030887160b2c735ffd20ea345fd90e2baab7b8fd6'
    if hashlib.sha256(constructor_lock_raw).hexdigest() != expected_lock_sha:
        raise ValueError('historical constructor lock identity')
    for relative, digest in constructor_lock['sourceAndEvidenceSha256'].items():
        add(relative, digest)

    # The historical constructor loads this exact S0-S4 driver. Mirror only
    # the paths it names through its pinned preparation and admission locks.
    driver_lock_path = view / 'tests/consumer-derivatives-v2/inputs.lock.json'
    driver_lock = json.loads(driver_lock_path.read_bytes())
    plan = Path('artifacts/consumer-derivatives-v2-plan/c3352edf-6caa-404e-b278-76cc6b87ec54')
    prep_manifest_rel = plan / 'preparation-source-sha256.json'
    add(prep_manifest_rel.as_posix(),
        'b4c4842a69d610ad61eb8b18a040b9077f4f2c8599940ea08304443e39fb0c09')
    prep_manifest = json.loads((view / prep_manifest_rel).read_bytes())
    for name, digest in prep_manifest.items():
        add((plan / 'qualification-source' / name).as_posix(), digest)
    prep_lock = json.loads((view / plan / 'qualification-source/inputs.lock.json').read_bytes())
    for name in ('baselineReceipt', 'baselineArchive', 'candidateManifest', 'toolchainSidecar', 'ownedProcessSource'):
        record = prep_lock[name]
        add(record['path'], record['sha256'])
    for relative, digest in prep_lock['successorQualificationSources'].items():
        add(relative, digest)
    for name, digest in prep_lock['candidateCatalogFiles'].items():
        add('staging/consumer-derivatives-v2/' + name, digest)
    root = Path(prep_lock['toolchainRoot'])
    for name, digest in {**prep_lock['toolchainCoreSha256'],
                         **prep_lock['toolchainInitdbSha256']}.items():
        add((root / 'Postgres.app' / name).as_posix(), digest)
    add((root / 'summary.json').as_posix(), prep_lock['toolchainSummarySha256'])
    add((root / 'acquisition-receipt.json').as_posix(),
        prep_lock['acquisitionReceiptSha256'])
    manifest = json.loads((view / prep_lock['candidateManifest']['path']).read_bytes())
    for name, digest in manifest.items():
        add('staging/consumer-derivatives-v2/' + name, digest)
    # These are separately pinned in the driver lock and must agree with the
    # preparation lock before they enter the historical view.
    for relative, digest in driver_lock.get('dependenciesSha256', {}).items():
        candidate = ROOT / relative
        try:
            raw = candidate.read_bytes()
        except OSError:
            continue
        if hashlib.sha256(raw).hexdigest() == digest:
            add(relative, digest)


class RunnerViews(unittest.TestCase):
    def test_runner_dependencies_on_exact_320f_view(self):
        inventory_mod = _load(HERE / 'runner-materialize.py', 'runner_view_materializer')
        view = _new_view('.ctas-runner-view-')
        try:
            report = inventory_mod.materialize(view)
            self.assertFalse(report['fullS5Qualified'])
            entry = view / 'tests/consumer-derivatives-v2-s5-pre012-ctas-supervised/s5.py'
            self.assertEqual(hashlib.sha256(entry.read_bytes()).hexdigest(),
                             'b67c8900a3a3a78d6d329a7dc8d1dce9072b2c99336522a8a44ce409ba9fb4b6')
            recorder = view / 'tests/consumer-fixture-evidence/recording.py'
            self.assertEqual(hashlib.sha256(recorder.read_bytes()).hexdigest(),
                             '320f62eca99763416ab4b9058cf29baec69042bfe77794eebd9364484c169c4f')
            module = _load(entry, 'ctas_supervised_runner_source_only')
            result = module.dependencies()
            self.assertEqual(len(result), 4)
            prior, helper, protocol, modules = result
            self.assertEqual(Path(prior.__file__),
                             view / 'tests/consumer-derivatives-v2-s5-admission-supervised/s5.py')
            self.assertEqual(Path(prior.ROOT), view)
            self.assertEqual(Path(helper.ROOT), view)
            _supplement_constructor_inputs(view)
            extended = _load(view / 'tests/consumer-derivatives-v2-s5-pre012-extended/s5.py',
                             'runner_view_historical_extended')
            self.assertFalse(extended.dependencies()['fullS5Qualified'])
            constructor = extended.load_constructor()
            self.assertEqual(hashlib.sha256(Path(constructor.__file__).read_bytes()).hexdigest(),
                             '7edfc912fbc079812ac2e35ace9cd2d56505d12c4ffd7f399e22be676759a3fd')
            self.assertIsInstance(constructor.load_admitted(), tuple)
            self.assertEqual(Path(protocol.__file__),
                             view / 'tests/consumer-derivatives-v2-s5-pre012-ctas/protocol.py')
            self.assertFalse(module.dependencies.__name__ == 'main')
            self.assertEqual(DENIED, [])
        finally:
            if view.exists():
                _clean(view)

    def test_historical_extended_admission_on_existing_view(self):
        materializer = _load(HERE / 'materialize.py', 'historical_view_materializer')
        view = _new_view('.ctas-successor-view-')
        try:
            materializer.materialize(view)
            extended_path = view / 'tests/consumer-derivatives-v2-s5-pre012-extended/s5.py'
            extended = _load(extended_path, 'historical_extended_source_only')
            lock = extended.dependencies()
            self.assertFalse(lock['fullS5Qualified'])
            constructor = extended.load_constructor()
            self.assertEqual(hashlib.sha256(Path(constructor.__file__).read_bytes()).hexdigest(),
                             '7edfc912fbc079812ac2e35ace9cd2d56505d12c4ffd7f399e22be676759a3fd')
            _supplement_constructor_inputs(view)
            self.assertIsInstance(constructor.load_admitted(), tuple)
            self.assertEqual(DENIED, [])
        finally:
            if view.exists():
                _clean(view)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RunnerViews))
    successful = result.wasSuccessful() and not DENIED
    status = 'PASS' if successful else 'FAIL'
    print(json.dumps({'runnerDependencies': status,
                      'historicalExtendedDependencies': status,
                      'historicalLoadConstructor': status,
                      'historicalLoadAdmitted': 'PASS_IN_A_AND_B' if successful else 'FAIL',
                      'missingPath': None,
                      'deniedEvents': DENIED, 'actualCTASCasesExecuted': 0,
                      'fullS5Qualified': False}))
    raise SystemExit(0 if successful else 1)
