"""Bounded, instance-only evidence recording; never launches a process.

Preservation boundary: frozen helpers use text=True (including newline decoding),
and command history replaces work/repository paths. Preserve that existing text,
not original OS pipe bytes. SQL record stdout is the unmodified helper string.
"""
import collections
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import zlib

VERSION = 'consumer-fixture-evidence-v2'
PRESERVATION = 'legacy text=True/newline decoding; command stdout path-cleaned; SQL stdout helper-returned; no OS-pipe-byte claim'
PHYSICAL_SCOPE = 'indexed files and owned directories before index publication; final reader includes index/manifest/receipt'
MAX_ITEM = 16 * 1024**2
MAX_BYTES = 256 * 1024**2
MAX_NAMES = 4096
MUTABLE = frozenset(('commands.json', 'extended-results.json', 'admission-results.json',
                     'transition-manifest.json'))
EXCLUSIONS = ('storage-index.json', 'transition-manifest.json',
              'completion-receipt.json', 'completion-receipt.pending.json')


class EvidenceError(ValueError):
    pass


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode('utf-8')


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise EvidenceError('duplicate JSON member')
            result[key] = value
        return result
    def invalid_constant(value):
        raise EvidenceError('nonfinite JSON number')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise EvidenceError('invalid evidence JSON') from exc


def stdout_refs(value):
    return [item['stdout'] for item in (value if isinstance(value, list) else [value])
            if isinstance(item, dict) and isinstance(item.get('stdout'), dict)
            and item['stdout'].get('encoding') == 'gzip-utf8-v1']


def component(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,179}', name) or name in ('.', '..'):
        raise EvidenceError('invalid evidence path component')
    return name


def relative(name):
    if not isinstance(name, str) or not name or len(name.split('/')) > 2:
        raise EvidenceError('invalid evidence relative path')
    return '/'.join(component(part) for part in name.split('/'))


def no_symlinks(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise EvidenceError('symlink evidence path')


def read_regular(path, limit=MAX_ITEM):
    no_symlinks(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_size > limit:
            raise EvidenceError('invalid evidence file identity or length')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        if len(raw) > limit or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise EvidenceError('evidence changed during read')
        return raw
    finally:
        os.close(fd)


class EvidenceStore:
    """One new root/budget shared by a single fixture or sequential case scopes."""
    def __init__(self, root, *, max_bytes=MAX_BYTES, max_item=MAX_ITEM,
                 max_names=MAX_NAMES, reserve_bytes=8 * 1024**2, threshold=64 * 1024):
        self.root = Path(root).absolute()
        no_symlinks(self.root)
        if self.root.resolve() != self.root:
            raise EvidenceError('evidence root must be canonical')
        if not 0 < max_item <= MAX_ITEM or not 16 <= max_names <= MAX_NAMES or not 0 < reserve_bytes < max_bytes <= MAX_BYTES:
            raise EvidenceError('invalid evidence limits')
        if not 0 <= threshold <= max_item:
            raise EvidenceError('invalid compression threshold')
        self.root.mkdir(mode=0o700, exist_ok=False)
        self.max_bytes, self.max_item, self.max_names = max_bytes, max_item, max_names
        self.reserve_bytes, self.threshold = reserve_bytes, threshold
        self.files, self.directories, self.blobs = {}, {}, {}
        self.failures, self.cleanup_events = [], []
        self.incomplete = False
        self.sealed = False
        self.event_count = 0
        self._remember_directory(self.root)

    def _remember_directory(self, path):
        s = path.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
            raise EvidenceError('owned evidence directory must be 0700')
        self.directories[str(path)] = (s.st_dev, s.st_ino, s.st_uid, s.st_mode)

    def scope(self, name=''):
        if not name:
            return self.root
        component(name)
        path = self.root / name
        if str(path) not in self.directories:
            if self.sealed:
                raise EvidenceError('sealed recording')
            self._capacity(0)
            path.mkdir(mode=0o700, exist_ok=False)
            self._remember_directory(path)
        self._audit()
        return path

    def _path(self, name):
        name = relative(name)
        path = self.root / name
        if str(path.parent) not in self.directories:
            raise EvidenceError('unknown evidence scope')
        no_symlinks(path)
        return path

    def _audit(self):
        links = collections.Counter()
        allocated = 0
        seen = set()
        for name, expected in self.directories.items():
            p = Path(name); no_symlinks(p); s = p.lstat()
            if (s.st_dev, s.st_ino, s.st_uid, s.st_mode) != expected:
                raise EvidenceError('evidence directory identity changed')
            allocated += s.st_blocks * 512
        for name, item in self.files.items():
            p = self._path(name); s = p.lstat()
            if not stat.S_ISREG(s.st_mode) or (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_size) != item['identity']:
                raise EvidenceError('evidence file identity changed')
            key = (s.st_dev, s.st_ino)
            links[key] += 1
            if key not in seen:
                seen.add(key); allocated += s.st_blocks * 512
        for name in self.files:
            s = self._path(name).lstat()
            if s.st_nlink != links[(s.st_dev, s.st_ino)]:
                raise EvidenceError('unexpected evidence hardlink')
        actual = set()
        for directory in self.directories:
            for p in Path(directory).iterdir():
                if str(p) in self.directories:
                    continue
                actual.add(str(p.relative_to(self.root)))
        if actual != set(self.files):
            raise EvidenceError('untracked evidence output')
        if allocated > self.max_bytes or len(self.files) + len(self.directories) - 1 > self.max_names:
            raise EvidenceError('evidence resource limit exceeded')
        return allocated

    def _capacity(self, length, new_names=1, emergency=False):
        if length > self.max_item:
            raise EvidenceError('evidence item limit exceeded')
        used = self._audit()
        # Reserve one temporary inode even when replacing an existing name.
        limit = self.max_bytes if emergency else self.max_bytes - self.reserve_bytes
        names = self.max_names if emergency else self.max_names - 8
        block = max(4096, os.statvfs(self.root).f_frsize)
        extra = ((length + block - 1) // block) * block
        if used + extra > limit or len(self.files) + len(self.directories) - 1 + max(1, new_names) > names:
            raise EvidenceError('evidence budget exhausted')

    def _remember(self, name, raw, role):
        s = self._path(name).lstat()
        self.files[name] = dict(sha256=digest(raw), bytes=len(raw), role=role,
            identity=(s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_size))

    def _verify(self, name):
        self._audit()
        raw = read_regular(self._path(name), self.max_item)
        item = self.files[name]
        if len(raw) != item['bytes'] or digest(raw) != item['sha256']:
            raise EvidenceError('evidence digest changed')
        return raw

    def _publish(self, name, raw, role, *, mutable=False, emergency=False):
        path = self._path(name)
        if name in self.files:
            self._verify(name)
            if not mutable:
                if self.files[name]['sha256'] != digest(raw):
                    raise EvidenceError('immutable output changed')
                return digest(raw)
            if self.files[name]['role'] != 'mutable':
                raise EvidenceError('immutable output cannot become mutable')
        elif path.exists():
            raise EvidenceError('unexpected output already exists')
        self._capacity(len(raw), emergency=emergency)
        temp = path.parent / ('tmp-' + secrets.token_hex(16))
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        temp_identity = os.fstat(fd)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(raw); stream.flush(); os.fsync(fd)
            os.fchmod(fd, 0o600 if mutable else 0o444)
            s = os.fstat(fd)
            used = self._allocated_without_temp()
            limit = self.max_bytes if emergency else self.max_bytes - self.reserve_bytes
            if used + s.st_blocks * 512 > limit:
                raise EvidenceError('temporary evidence exceeds budget')
            no_symlinks(path)
            if path.exists() and name not in self.files:
                raise EvidenceError('output publication collision')
            os.replace(temp, path)
            self._remember(name, raw, 'mutable' if mutable else role)
        finally:
            os.close(fd)
            if temp.exists():
                s = temp.lstat()
                if (s.st_dev, s.st_ino, s.st_uid) == (temp_identity.st_dev, temp_identity.st_ino, os.getuid()):
                    temp.unlink()  # Only this exclusive, new-run temporary file.
        self._audit()
        return digest(raw)

    def _allocated_without_temp(self):
        seen = set(); total = 0
        for p in [Path(p) for p in self.directories] + [self._path(n) for n in self.files]:
            s = p.lstat(); key = (s.st_dev, s.st_ino)
            if key not in seen:
                seen.add(key); total += s.st_blocks * 512
        return total

    def _blob(self, raw, kind):
        prefix, suffix = {'gzip': ('stdout-', '.gz'), 'json': ('blob-', '.json'),
                          'bytes': ('bytes-', '.bin')}[kind]
        name = prefix + digest(raw) + suffix
        self._publish(name, raw, 'blob-' + kind)
        self.blobs[name] = dict(sha256=digest(raw), bytes=len(raw), kind=kind)
        return name

    def compact(self, text):
        if not isinstance(text, str):
            raise EvidenceError('stdout must be text')
        raw = text.encode('utf-8')
        if len(raw) > self.max_item:
            raise EvidenceError('logical stdout limit exceeded')
        if len(raw) <= self.threshold:
            return text
        packed = gzip.compress(raw, compresslevel=1, mtime=0)
        name = self._blob(packed, 'gzip')
        result = dict(encoding='gzip-utf8-v1', blob=name, storedSha256=digest(packed),
                    storedBytes=len(packed), logicalSha256=digest(raw), logicalBytes=len(raw))
        self.blobs[name]['stdout'] = result
        return result

    def fail(self, exc):
        self.incomplete = True
        if len(self.failures) < 16:
            self.failures.append(type(exc).__name__ + ': ' + str(exc)[:160])

    def _alias(self, path_name, raw, blob, role, refs=None):
        if path_name in self.files:
            existing = self._verify(path_name)
            if existing != raw or self.files[path_name]['role'] != role:
                raise EvidenceError('immutable alias changed')
            return digest(existing)
        self._capacity(0)
        destination = self._path(path_name)
        if destination.exists():
            raise EvidenceError('alias publication collision')
        temp = destination.parent / ('tmp-' + secrets.token_hex(16))
        os.link(self._path(blob), temp, follow_symlinks=False)
        try:
            os.replace(temp, destination)
            self._remember(path_name, raw, role)
            self.files[path_name]['blob'] = blob
            if refs is not None:
                self.files[path_name]['stdoutRefs'] = refs
        finally:
            if temp.exists():
                current = temp.lstat(); source = self._path(blob).lstat()
                if (current.st_dev, current.st_ino, current.st_uid) == (source.st_dev, source.st_ino, os.getuid()):
                    temp.unlink()
        self._audit()
        return digest(raw)

    def save_bytes(self, name, raw, *, scope=''):
        """Publish supplied exact bytes; never registers or reads an outside file."""
        try:
            component(name)
            if name.startswith(('blob-', 'bytes-', 'stdout-', 'tmp-')) or name in MUTABLE | set(EXCLUSIONS) | {'recording-failure.json'}:
                raise EvidenceError('reserved byte output name')
            if type(raw) is not bytes:
                raise EvidenceError('byte output requires immutable bytes')
            if self.incomplete or self.sealed:
                raise EvidenceError('recording incomplete or sealed')
            self.scope(scope)
            path_name = (scope + '/' if scope else '') + name
            return self._alias(path_name, raw, self._blob(raw, 'bytes'), 'alias-bytes')
        except (OSError, EvidenceError, UnicodeError) as exc:
            self.fail(exc)
            raise

    def save(self, name, value, *, scope=''):
        try:
            component(name)
            if name.startswith(('blob-', 'bytes-', 'stdout-', 'tmp-')) or name in ('storage-index.json', 'recording-failure.json', 'completion-receipt.json', 'completion-receipt.pending.json'):
                raise EvidenceError('reserved evidence output name')
            if self.incomplete and name != 'transition-manifest.json':
                raise EvidenceError('recording is incomplete')
            if self.incomplete:
                if not isinstance(value, dict):
                    raise EvidenceError('failure manifest must be an object')
                value = dict(value, status='FAILED_RECORDING_INCOMPLETE', authoritative=False,
                    recordingComplete=False, qualificationAllowed=False, fullS5Qualified=False,
                    boundedSubsetCompleted=False, extendedCompleted=False, admissionFaultsCompleted=False,
                    qualification={key: False for key in value.get('qualification', {})})
            if self.sealed and name != 'transition-manifest.json':
                raise EvidenceError('recording already sealed')
            self.scope(scope)
            if re.fullmatch(r'sql-[0-9]+\.json', name) and isinstance(value, dict) and isinstance(value.get('stdout'), str):
                value = dict(value, stdout=self.compact(value['stdout']))
            raw = encoded(value)
            path_name = (scope + '/' if scope else '') + name
            refs = stdout_refs(value)
            if name in MUTABLE:
                result = self._publish(path_name, raw, 'mutable', mutable=True,
                                       emergency=name == 'transition-manifest.json')
                self.files[path_name]['stdoutRefs'] = refs
                return result
            blob = self._blob(raw, 'json')
            return self._alias(path_name, raw, blob, 'alias', refs)
        except (OSError, EvidenceError, UnicodeError) as exc:
            self.fail(exc)
            raise

    def failure_report(self):
        """Bounded reserved output; caller must still report unqualified failure."""
        self.incomplete = True
        value = dict(format=VERSION, recordingComplete=False, qualificationAllowed=False,
                     failures=self.failures, cleanupEvents=self.cleanup_events[-8:])
        raw = encoded(value)
        if len(raw) > min(self.max_item, 64 * 1024):
            raw = encoded(dict(format=VERSION, recordingComplete=False,
                               qualificationAllowed=False, failures=self.failures))
        return self._publish('recording-failure.json', raw, 'mutable', mutable=True, emergency=True)

    @staticmethod
    def _seal_stat(value):
        # atime can change from our reads. These fields must remain stable.
        return (value.st_dev, value.st_ino, value.st_uid, value.st_mode,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns,
                value.st_nlink, value.st_blocks)

    def _seal_registry(self):
        # Only the index registration may change during its known publication.
        value = dict(files={n: v for n, v in self.files.items() if n != 'storage-index.json'},
                     directories=self.directories, blobs=self.blobs, eventCount=self.event_count,
                     incomplete=self.incomplete, failures=self.failures,
                     cleanupEvents=self.cleanup_events, sealed=self.sealed)
        return digest(json.dumps(value).encode('utf-8'))

    def _seal_read(self, name, expected_stat):
        """One bounded stable-fd hash; caller owns the enclosing batch audits."""
        path = self._path(name)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or self._seal_stat(before) != expected_stat:
                raise EvidenceError('seal file identity changed before read')
            total = 0; hasher = hashlib.sha256()
            while True:
                chunk = os.read(fd, min(64 * 1024, self.max_item + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_item:
                    raise EvidenceError('seal file exceeds item limit')
                hasher.update(chunk)
            if self._seal_stat(os.fstat(fd)) != expected_stat:
                raise EvidenceError('seal file changed during read')
            actual = hasher.hexdigest()
            if total != self.files[name]['bytes'] or actual != self.files[name]['sha256']:
                raise EvidenceError('seal file hash or length mismatch')
            return actual
        finally:
            os.close(fd)

    def _seal_check(self, files, directories, registry):
        if self._seal_registry() != registry:
            raise EvidenceError('seal registry changed during batch')
        for name, expected in files.items():
            if self._seal_stat(self._path(name).lstat()) != expected:
                raise EvidenceError('seal batch file metadata changed')
        for name, expected in directories.items():
            if self._seal_stat(Path(name).lstat()) != expected:
                raise EvidenceError('seal batch directory metadata changed')

    def seal(self):
        """Linear audited hash batch; never re-audit the namespace per file."""
        try:
            self._audit()
            for item in self.files.values():
                for ref in item.get('stdoutRefs', []):
                    if self.blobs.get(ref.get('blob'), {}).get('stdout') != ref:
                        self.fail(EvidenceError('unregistered stdout reference'))
            if self.incomplete:
                self.failure_report()
                self._audit()

            names = tuple(self.files)
            registry = self._seal_registry()
            files = {n: self._seal_stat(self._path(n).lstat()) for n in names}
            directories = {n: self._seal_stat(Path(n).lstat()) for n in self.directories}
            verified = {n: self._seal_read(n, files[n]) for n in names}
            self._audit()
            self._seal_check(files, directories, registry)

            value = dict(format=VERSION, recordingComplete=not self.incomplete,
                qualificationAllowed=not self.incomplete,
                preservation=PRESERVATION,
                limits=dict(uniqueAllocatedBytes=self.max_bytes, itemBytes=self.max_item,
                            names=self.max_names, reservedBytes=self.reserve_bytes),
                files={n: {k: v for k, v in item.items() if k != 'identity'} for n, item in self.files.items() if n not in EXCLUSIONS},
                blobs=self.blobs, exclusions=list(EXCLUSIONS),
                eventCount=self.event_count,
                scopes=sorted(str(Path(p).relative_to(self.root)) for p in self.directories if Path(p) != self.root),
                physical=self.physical(indexed_only=True))
            raw = encoded(value)
            self._publish('storage-index.json', raw, 'mutable', mutable=True, emergency=True)

            # Publication may add/replace this one root output and update the
            # root directory timestamps. Every other registration must persist.
            if set(self.files) != set(names) | {'storage-index.json'}:
                raise EvidenceError('unexpected output during index publication')
            index_stat = self._path('storage-index.json').lstat()
            if stat.S_IMODE(index_stat.st_mode) != 0o600 or index_stat.st_uid != os.getuid() or index_stat.st_nlink != 1:
                raise EvidenceError('invalid published index identity')
            index_identity = (index_stat.st_dev, index_stat.st_ino, index_stat.st_uid,
                              index_stat.st_mode, index_stat.st_size)
            expected_index = dict(sha256=digest(raw), bytes=len(raw), role='mutable', identity=index_identity)
            if self.files['storage-index.json'] != expected_index:
                raise EvidenceError('index registration changed during publication')
            final_files = dict(files, **{'storage-index.json': self._seal_stat(index_stat)})
            final_directories = dict(directories)
            final_directories[str(self.root)] = self._seal_stat(self.root.lstat())
            verified['storage-index.json'] = self._seal_read('storage-index.json', final_files['storage-index.json'])
            self._audit()
            self._seal_check(final_files, final_directories, registry)
            if self.files['storage-index.json'] != expected_index:
                raise EvidenceError('index registration changed during final verification')
            self.sealed = True
            return {n: pin for n, pin in verified.items() if n not in (
                'transition-manifest.json', 'completion-receipt.json', 'completion-receipt.pending.json')}
        except (OSError, EvidenceError, UnicodeError) as exc:
            self.fail(exc)
            raise

    def physical(self, *, indexed_only=False):
        allocated = self._audit(); counts = collections.Counter()
        files = {n: v for n, v in self.files.items() if not indexed_only or n not in EXCLUSIONS}
        if indexed_only:
            allocated = sum(Path(p).stat().st_blocks * 512 for p in self.directories)
        seen = set()
        for name in files:
            s = self._path(name).lstat(); counts[(s.st_dev, s.st_ino)] += 1
            if indexed_only and (s.st_dev, s.st_ino) not in seen:
                allocated += s.st_blocks * 512
                seen.add((s.st_dev, s.st_ino))
        return dict(uniqueAllocatedBytes=allocated, logicalNamedBytes=sum(v['bytes'] for v in files.values()),
                    names=len(files) + len(self.directories) - 1,
                    fileNames=len(files), directoryNames=len(self.directories) - 1,
                    scope=PHYSICAL_SCOPE if indexed_only else 'all currently tracked outputs and scopes',
                    uniqueFileInodes=len(counts),
                    links=[dict(device=d, inode=i, expectedNlink=n) for (d, i), n in sorted(counts.items())])


class RecordedEvents(list):
    def __init__(self, store, scope=''):
        if scope:
            component(scope)
            if str(store.root / scope) not in store.directories:
                raise EvidenceError('unknown recorded event scope')
        super().__init__(); self.store = store; self.cleanup = False; self.scope = scope

    def append(self, entry):
        copied = dict(entry)
        self.store.event_count += 1
        try:
            if not self.cleanup and self.store.event_count > self.store.max_names - 8:
                raise EvidenceError('command event count exhausted')
            if self.store.incomplete:
                raise EvidenceError('recording already incomplete')
            copied['stdout'] = self.store.compact(entry['stdout'])
        except (OSError, EvidenceError, UnicodeError) as exc:
            self.store.fail(exc)
            copied = {k: entry[k] for k in ('id', 'label', 'returncode') if k in entry}
            copied['recordingIncomplete'] = True
            # This explicitly incomplete fallback is not accepted as full proof.
            if isinstance(entry.get('stderr'), str) and len(entry['stderr'].encode()) <= 4096:
                copied['stderr'] = entry['stderr']
        if self.cleanup:
            self.store.cleanup_events.append(dict(copied, scope=self.scope))
            del self.store.cleanup_events[:-8]
        # Bound retained metadata after failure; qualification is already false.
        if not self.store.incomplete or len(self) < 4096:
            super().append(copied)


def fixture_class(base_fixture):
    """Return a subclass; instantiate with recording_store and recording_scope.

    All ordinary positional arguments remain those of the frozen Fixture.
    No module globals, process runner, command strings, or returned rows change.
    """
    class RecordedFixture(base_fixture):
        def __init__(self, *args, recording_store, recording_scope='', **kwargs):
            super().__init__(*args, **kwargs)
            self.recording_store = recording_store
            self.recording_scope = recording_scope
            if self.evidence.absolute() != recording_store.scope(recording_scope):
                raise EvidenceError('fixture evidence does not match recorder scope')
            self.events = RecordedEvents(recording_store, recording_scope)

        def command(self, *args, cleanup=False, **kwargs):
            before = self.events.cleanup; self.events.cleanup = cleanup
            try:
                return super().command(*args, cleanup=cleanup, **kwargs)
            finally:
                self.events.cleanup = before

        def save(self, name, value):
            try:
                return self.recording_store.save(name, value, scope=self.recording_scope)
            except (OSError, EvidenceError, UnicodeError):
                if self.events.cleanup:
                    try:
                        self.recording_store.failure_report()
                    except (OSError, EvidenceError):
                        pass
                raise  # Frozen cleanup=True command uses try_save and continues.
    return RecordedFixture


class EvidenceReader:
    """Strict reader for new storage format; ordinary catalog JSON stays ordinary."""
    def __init__(self, root, *, expected_index_sha256):
        self.root = Path(root).absolute(); no_symlinks(self.root)
        if self.root.resolve() != self.root:
            raise EvidenceError('reader root must be canonical')
        s = self.root.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
            raise EvidenceError('invalid evidence reader root')
        raw = read_regular(self.root / 'storage-index.json')
        if digest(raw) != expected_index_sha256:
            raise EvidenceError('storage index pin mismatch')
        self.index_pin = expected_index_sha256
        self.index = strict_json(raw)
        self._schema()
        if len(raw) > self.item_limit:
            raise EvidenceError('index exceeds declared item limit')

    @staticmethod
    def _fields(value, keys):
        if type(value) is not dict or set(value) != set(keys):
            raise EvidenceError('invalid closed index object')

    @staticmethod
    def _integer(value, low, high):
        if type(value) is not int or not low <= value <= high:
            raise EvidenceError('invalid indexed integer or bound')

    @staticmethod
    def _hash(value):
        if type(value) is not str or not re.fullmatch('[0-9a-f]{64}', value):
            raise EvidenceError('invalid indexed SHA256')

    def _reference(self, value):
        self._fields(value, ('encoding', 'blob', 'storedSha256', 'storedBytes', 'logicalSha256', 'logicalBytes'))
        if value['encoding'] != 'gzip-utf8-v1':
            raise EvidenceError('invalid stdout encoding')
        self._hash(value['storedSha256']); self._hash(value['logicalSha256'])
        for key in ('storedBytes', 'logicalBytes'):
            self._integer(value[key], 0, self.item_limit)
        component(value['blob'])
        if value['blob'] != 'stdout-' + value['storedSha256'] + '.gz':
            raise EvidenceError('stdout name does not match stored digest')

    def _schema(self):
        index = self.index
        self._fields(index, ('format', 'recordingComplete', 'qualificationAllowed', 'preservation',
                            'limits', 'files', 'blobs', 'exclusions', 'eventCount', 'scopes', 'physical'))
        if index['format'] != VERSION or index['preservation'] != PRESERVATION:
            raise EvidenceError('unknown recording format or preservation boundary')
        if any(type(index[key]) is not bool for key in ('recordingComplete', 'qualificationAllowed')) or index['recordingComplete'] != index['qualificationAllowed']:
            raise EvidenceError('completion flags must be matching booleans')
        if index['exclusions'] != list(EXCLUSIONS):
            raise EvidenceError('invalid index exclusions')
        limits = index['limits']
        self._fields(limits, ('uniqueAllocatedBytes', 'itemBytes', 'names', 'reservedBytes'))
        self._integer(limits['uniqueAllocatedBytes'], 2, MAX_BYTES)
        self._integer(limits['itemBytes'], 1, MAX_ITEM)
        self._integer(limits['names'], 16, MAX_NAMES)
        self._integer(limits['reservedBytes'], 1, limits['uniqueAllocatedBytes'] - 1)
        self.item_limit = limits['itemBytes']
        self._integer(index['eventCount'], 0, limits['names'] + 8)
        if index['qualificationAllowed'] and index['eventCount'] > limits['names']:
            raise EvidenceError('qualified event count exceeds limit')
        scopes = index['scopes']
        if type(scopes) is not list or len(scopes) > limits['names']:
            raise EvidenceError('invalid scope list')
        for scope in scopes:
            component(scope)
        if scopes != sorted(set(scopes)):
            raise EvidenceError('duplicate or unordered scopes')
        files, blobs = index['files'], index['blobs']
        if type(files) is not dict or type(blobs) is not dict or len(files) + len(scopes) + 1 > limits['names']:
            raise EvidenceError('invalid indexed output maps or count')
        if 'recording-failure.json' in files and index['qualificationAllowed']:
            raise EvidenceError('failure output cannot coexist with qualification')
        blob_names = set()
        for name, item in files.items():
            relative(name)
            if name in EXCLUSIONS or ('/' in name and name.split('/')[0] not in scopes):
                raise EvidenceError('excluded output or unknown scope in index')
            if type(item) is not dict or type(item.get('role')) is not str:
                raise EvidenceError('invalid output descriptor')
            role = item['role']; keys = {'sha256', 'bytes', 'role'}
            if role == 'alias':
                keys |= {'blob', 'stdoutRefs'}
            elif role == 'alias-bytes':
                keys |= {'blob'}
            elif role == 'mutable':
                if name != 'recording-failure.json':
                    if Path(name).name not in MUTABLE:
                        raise EvidenceError('unknown mutable output')
                    keys |= {'stdoutRefs'}
            elif role in ('blob-json', 'blob-bytes', 'blob-gzip'):
                blob_names.add(name)
            else:
                raise EvidenceError('unknown output role')
            self._fields(item, keys)
            self._hash(item['sha256']); self._integer(item['bytes'], 0, self.item_limit)
            if role.startswith('blob-'):
                kind = role[5:]
                prefix, suffix = {'json': ('blob-', '.json'), 'bytes': ('bytes-', '.bin'), 'gzip': ('stdout-', '.gz')}[kind]
                if name != prefix + item['sha256'] + suffix:
                    raise EvidenceError('blob filename does not match role and digest')
            elif Path(name).name.startswith(('blob-', 'bytes-', 'stdout-', 'tmp-')):
                raise EvidenceError('reserved alias or mutable filename')
            if role in ('alias', 'alias-bytes') and Path(name).name in MUTABLE | set(EXCLUSIONS) | {'recording-failure.json'}:
                raise EvidenceError('reserved immutable alias filename')
            if 'stdoutRefs' in item:
                if type(item['stdoutRefs']) is not list or len(item['stdoutRefs']) > limits['names']:
                    raise EvidenceError('invalid stdout reference list')
                for ref in item['stdoutRefs']:
                    self._reference(ref)
            if role in ('alias', 'alias-bytes'):
                component(item['blob'])
        if set(blobs) != blob_names:
            raise EvidenceError('blob map must exactly cover blob files')
        for name, blob in blobs.items():
            if type(blob) is not dict or blob.get('kind') not in ('json', 'bytes', 'gzip'):
                raise EvidenceError('unknown blob kind')
            keys = {'sha256', 'bytes', 'kind'} | ({'stdout'} if blob['kind'] == 'gzip' else set())
            self._fields(blob, keys)
            file = files[name]
            if file['role'] != 'blob-' + blob['kind'] or file['sha256'] != blob['sha256'] or type(blob['bytes']) is not int or file['bytes'] != blob['bytes']:
                raise EvidenceError('blob and file descriptors disagree')
            if blob['kind'] == 'gzip':
                self._reference(blob['stdout'])
                ref = blob['stdout']
                if ref['blob'] != name or ref['storedSha256'] != blob['sha256'] or ref['storedBytes'] != blob['bytes']:
                    raise EvidenceError('gzip descriptor disagrees with its reference')
        for name, item in files.items():
            if item['role'] in ('alias', 'alias-bytes'):
                blob = blobs.get(item['blob'])
                kind = 'json' if item['role'] == 'alias' else 'bytes'
                if blob is None or blob['kind'] != kind or item['sha256'] != blob['sha256'] or item['bytes'] != blob['bytes']:
                    raise EvidenceError('alias and blob descriptors disagree')
            for ref in item.get('stdoutRefs', []):
                if blobs.get(ref['blob'], {}).get('stdout') != ref:
                    raise EvidenceError('unregistered or mismatched stdout reference')
        physical = index['physical']
        self._fields(physical, ('uniqueAllocatedBytes', 'logicalNamedBytes', 'names', 'fileNames',
                              'directoryNames', 'scope', 'uniqueFileInodes', 'links'))
        for key in ('names', 'fileNames', 'directoryNames', 'uniqueFileInodes'):
            self._integer(physical[key], 0, limits['names'])
        self._integer(physical['uniqueAllocatedBytes'], 0, limits['uniqueAllocatedBytes'])
        self._integer(physical['logicalNamedBytes'], 0, limits['names'] * self.item_limit)
        if physical['scope'] != PHYSICAL_SCOPE or physical['fileNames'] != len(files) or physical['directoryNames'] != len(scopes) or physical['names'] != len(files) + len(scopes) or physical['logicalNamedBytes'] != sum(item['bytes'] for item in files.values()):
            raise EvidenceError('inconsistent physical counter scope')
        if type(physical['links']) is not list or len(physical['links']) != physical['uniqueFileInodes']:
            raise EvidenceError('invalid physical link list')
        seen = set(); link_count = 0
        for link in physical['links']:
            self._fields(link, ('device', 'inode', 'expectedNlink'))
            for key in ('device', 'inode'):
                self._integer(link[key], 1, 2**64 - 1)
            self._integer(link['expectedNlink'], 1, limits['names'])
            identity = (link['device'], link['inode'])
            if identity in seen:
                raise EvidenceError('duplicate indexed physical inode')
            seen.add(identity); link_count += link['expectedNlink']
        if link_count != len(files):
            raise EvidenceError('physical link counts do not cover file names')

    def _raw(self, name):
        relative(name)
        if name not in self.index['files']:
            raise EvidenceError('unindexed evidence file')
        raw = read_regular(self.root / name, self.item_limit)
        item = self.index['files'][name]
        if len(raw) != item['bytes'] or digest(raw) != item['sha256']:
            raise EvidenceError('evidence hash or length mismatch')
        return raw

    def stdout(self, value):
        if isinstance(value, str):
            try:
                length = len(value.encode('utf-8'))
            except UnicodeError as exc:
                raise EvidenceError('stdout is not UTF-8') from exc
            if length > self.item_limit:
                raise EvidenceError('inline stdout exceeds declared limit')
            return value
        self._reference(value)
        if self.index['blobs'].get(value['blob'], {}).get('stdout') != value:
            raise EvidenceError('stdout reference does not match indexed blob')
        packed = self._raw(value['blob'])
        if len(packed) != value['storedBytes'] or digest(packed) != value['storedSha256']:
            raise EvidenceError('stored stdout mismatch')
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            raw = inflater.decompress(packed, value['logicalBytes'] + 1)
        except zlib.error as exc:
            raise EvidenceError('invalid gzip stdout') from exc
        if len(raw) != value['logicalBytes'] or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail or digest(raw) != value['logicalSha256']:
            raise EvidenceError('stdout bounds, member, or digest mismatch')
        try:
            return raw.decode('utf-8', errors='strict')
        except UnicodeError as exc:
            raise EvidenceError('stdout is not UTF-8') from exc

    def read(self, name):
        if self.index['files'].get(name, {}).get('role') in ('alias-bytes', 'blob-bytes'):
            raise EvidenceError('byte outputs require raw()')
        value = strict_json(self._raw(name))
        if Path(name).name == 'commands.json':
            if not isinstance(value, list):
                raise EvidenceError('commands must be a list')
            return [dict(item, stdout=self.stdout(item['stdout'])) if 'stdout' in item else item for item in value]
        if re.fullmatch(r'sql-[0-9]+\.json', Path(name).name) and isinstance(value, dict) and 'stdout' in value:
            return dict(value, stdout=self.stdout(value['stdout']))
        return value

    def raw(self, name):
        """Return exact verified stored bytes, including derived SQL/binary output."""
        return self._raw(name)

    def validate(self):
        self._schema()
        names = self.index['files']
        if len(names) + 1 > self.index['limits']['names']:
            raise EvidenceError('too many indexed outputs')
        links = collections.Counter(); seen = set(); allocated = 0
        for name in names:
            self._raw(name)
            s = (self.root / name).lstat(); key = (s.st_dev, s.st_ino)
            links[key] += 1
            if key not in seen:
                seen.add(key); allocated += s.st_blocks * 512
            if names[name]['role'].startswith(('alias', 'blob-')) and stat.S_IMODE(s.st_mode) != 0o444:
                raise EvidenceError('immutable output is writable')
            if names[name]['role'] == 'mutable' and (stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1):
                raise EvidenceError('mutable output is shared or not private')
            if names[name]['role'] in ('alias', 'alias-bytes'):
                blob = names[name].get('blob')
                expected_role = 'blob-json' if names[name]['role'] == 'alias' else 'blob-bytes'
                if blob not in names or names[blob]['role'] != expected_role:
                    raise EvidenceError('invalid alias blob')
                target = (self.root / blob).lstat()
                if (target.st_dev, target.st_ino) != key:
                    raise EvidenceError('alias is not its indexed internal hardlink')
            for ref in names[name].get('stdoutRefs', []):
                self.stdout(ref)
            if names[name]['role'] in ('alias', 'blob-json', 'mutable'):
                value = strict_json(self._raw(name))
                if names[name]['role'] != 'blob-json' and name != 'recording-failure.json' and stdout_refs(value) != names[name]['stdoutRefs']:
                    raise EvidenceError('JSON stdout references do not match index')
            if names[name]['role'] != 'alias-bytes' and (Path(name).name == 'commands.json' or re.fullmatch(r'sql-[0-9]+\.json', Path(name).name)):
                self.read(name)
        for blob in self.index['blobs'].values():
            if blob['kind'] == 'gzip':
                self.stdout(blob['stdout'])
        for name in names:
            s = (self.root / name).lstat()
            if s.st_nlink != links[(s.st_dev, s.st_ino)]:
                raise EvidenceError('unexpected indexed hardlink')
        expected_links = {(item['device'], item['inode']): item['expectedNlink'] for item in self.index['physical']['links']}
        if dict(links) != expected_links:
            raise EvidenceError('physical inode identities do not match index')
        actual = set(); all_inodes = set(); total_allocated = 0; directory_names = 0
        for p in self.root.rglob('*'):
            no_symlinks(p)
            s = p.lstat()
            if s.st_uid != os.getuid() or not (stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)):
                raise EvidenceError('unexpected evidence object')
            key = (s.st_dev, s.st_ino)
            if key not in all_inodes:
                all_inodes.add(key); total_allocated += s.st_blocks * 512
            if p.is_file():
                actual.add(str(p.relative_to(self.root)))
                if str(p.relative_to(self.root)) in EXCLUSIONS:
                    read_regular(p, self.item_limit)
                    if stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1:
                        raise EvidenceError('invalid index/manifest/receipt identity')
            else:
                if stat.S_IMODE(s.st_mode) != 0o700:
                    raise EvidenceError('evidence scope is not private')
                directory_names += 1
                if str(p.relative_to(self.root)) not in self.index['scopes']:
                    raise EvidenceError('unindexed evidence scope')
        total_allocated += self.root.stat().st_blocks * 512
        if actual - set(EXCLUSIONS) != set(names) or len(actual) + directory_names > self.index['limits']['names'] or total_allocated > self.index['limits']['uniqueAllocatedBytes']:
            raise EvidenceError('unindexed output or physical budget exceeded')
        self.physical_counts = dict(uniqueAllocatedBytes=total_allocated,
                                    names=len(actual) + directory_names,
                                    scope='all current run files and directories including index/manifest/receipt')
        if directory_names != len(self.index['scopes']) or digest(read_regular(self.root / 'storage-index.json', self.item_limit)) != self.index_pin:
            raise EvidenceError('scope or index changed during validation')
        return self.index['recordingComplete'] and self.index['qualificationAllowed']
