"""Separate raw-log admission for this public/schema-only fixture.

RLIMIT_FSIZE is a hard per-file logical-size cap inherited by all descendants.
Raw-log pair reservations bound logical retained/active output to512MiB and
reserve128MiB exclusively for cleanup. Allocated-byte scans are a conservative
admission check, not a filesystem-wide quota. PG data and256MiB compact evidence
have separate accounting. No arbitrary file is deleted by this policy.
"""
from pathlib import Path
from dataclasses import dataclass
import os
import re
import resource
import signal
import stat

MIB = 1024**2
STREAM_BYTES = 32*MIB
RAW_BYTES = 512*MIB
CLEANUP_RESERVED_BYTES = 128*MIB


class ResourceLimit(ValueError):pass


@dataclass(frozen=True, eq=False)
class Reservation:
    serial:int
    stdout:Path
    stderr:Path
    cleanup:bool


class ResourcePolicy:
    def __init__(self, *, resource_api=resource, signal_api=signal):
        self.resource_api = resource_api;self.signal_api = signal_api
        self.sigxfsz_ignored = False
        self.prepared = False;self.installed = False
        self.tokens = {};self.paths = {};self.next_serial = 0
        self.high_water_reserved = 0;self.high_water_observed = 0
        self.fixture_file_admission = None

    def prepare(self, work):
        if self.prepared:raise ResourceLimit('raw-log policy already prepared')
        work = Path(work)
        logs = work/'logs'
        if (not work.is_absolute() or work.resolve() != work
            or any(p.is_symlink() for p in (logs,work,*work.parents))):
            raise ResourceLimit('canonical owned raw-log directory required')
        info = logs.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid() or list(logs.iterdir())):
            raise ResourceLimit('new owned0700 raw-log directory required')
        self.logs = logs;self.logs_identity = (info.st_dev,info.st_ino)
        self.prepared = True

    def _verify_file_signal(self):
        api = self.signal_api
        if not hasattr(api,'SIGXFSZ') or api.getsignal(api.SIGXFSZ) != api.SIG_IGN:
            self.sigxfsz_ignored = False
            raise ResourceLimit('sole owner must ignore SIGXFSZ before inherited file cap')
        self.sigxfsz_ignored = True

    def install(self):
        if not self.prepared or self.installed:raise ResourceLimit('raw-log policy install order')
        self._verify_file_signal()
        api = self.resource_api
        api.setrlimit(api.RLIMIT_FSIZE,(STREAM_BYTES,STREAM_BYTES))
        if api.getrlimit(api.RLIMIT_FSIZE) != (STREAM_BYTES,STREAM_BYTES):
            raise ResourceLimit('fixed inherited32MiB file cap not installed')
        self.installed = True

    def _scan(self):
        if not self.installed:raise ResourceLimit('raw-log cap not installed before launch')
        self._verify_file_signal()
        api = self.resource_api
        if api.getrlimit(api.RLIMIT_FSIZE) != (STREAM_BYTES,STREAM_BYTES):
            raise ResourceLimit('inherited file cap changed')
        info = self.logs.lstat()
        if ((info.st_dev,info.st_ino) != self.logs_identity or not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()):
            raise ResourceLimit('owned raw-log directory changed')
        observed = 0
        for path in self.logs.iterdir():
            if path not in self.paths:raise ResourceLimit('unreserved raw-log file')
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode)&0o077 or info.st_size > STREAM_BYTES):
                raise ResourceLimit('raw-log file identity or cap changed')
            observed += max(info.st_size,info.st_blocks*512)
        self.high_water_observed = max(self.high_water_observed,observed)
        if observed > len(self.tokens)*2*STREAM_BYTES or observed > RAW_BYTES:
            raise ResourceLimit('observed raw-log allocation exceeds reservations')

    def reserve(self, name, stdout, stderr, *, cleanup=False):
        self._scan()
        if type(cleanup) is not bool:raise ResourceLimit('typed cleanup admission required')
        stdout,stderr = Path(stdout),Path(stderr)
        if (stdout == stderr or any(p.parent != self.logs or p in self.paths or p.exists()
            or p.is_symlink() for p in (stdout,stderr))):
            raise ResourceLimit('new unique owned log paths required')
        charged = (len(self.tokens)+1)*2*STREAM_BYTES
        if charged > (RAW_BYTES if cleanup else RAW_BYTES-CLEANUP_RESERVED_BYTES):
            raise ResourceLimit('raw-log aggregate/cleanup reserve exhausted')
        self.next_serial += 1
        token = Reservation(self.next_serial,stdout,stderr,cleanup)
        self.tokens[token.serial] = token
        self.paths[stdout] = token;self.paths[stderr] = token
        self.high_water_reserved = max(self.high_water_reserved,charged)
        return token

    def release(self, token):
        # Guardian is responsible for exact known-child identity/hash checks and
        # unlink. Merely passing another equal-looking token never releases it.
        if type(token) is not Reservation or self.tokens.get(token.serial) is not token:
            raise ResourceLimit('unknown raw-log reservation')
        if any(path.exists() or path.is_symlink() for path in (token.stdout,token.stderr)):
            raise ResourceLimit('verified log retirement required before release')
        for path in (token.stdout,token.stderr):del self.paths[path]
        del self.tokens[token.serial]

    def admit_fixture_files(self, data):
        """Inspect new initdb files before foreground PG, without changing SQL."""
        self._scan()
        data = Path(data)
        if data != self.logs.parent/'data' or data.is_symlink() or not data.is_dir():
            raise ResourceLimit('owned initialized data directory required')
        wal_sizes = [];count = 0;largest = 0
        for path in data.rglob('*'):
            info = path.lstat()
            if info.st_uid != os.getuid() or path.is_symlink():raise ResourceLimit('fixture data identity')
            if stat.S_ISDIR(info.st_mode):continue
            if not stat.S_ISREG(info.st_mode) or info.st_size > STREAM_BYTES:
                raise ResourceLimit('fixture file exceeds inherited32MiB cap')
            count += 1;largest = max(largest,info.st_size)
            if path.parent == data/'pg_wal' and re.fullmatch('[0-9A-F]{24}',path.name):wal_sizes.append(info.st_size)
        if not wal_sizes or any(size != 16*MIB for size in wal_sizes):
            raise ResourceLimit('initialized WAL segment must be exactly16MiB')
        self.fixture_file_admission = dict(initialRegularFiles=count,largestInitialFileBytes=largest,
            observedWalSegmentBytes=sorted(set(wal_sizes)),allInitialFilesWithinHardCap=True)
        return dict(self.fixture_file_admission)

    def metadata(self):
        return dict(scope='public-schema raw stdout/stderr only; PG data and compact evidence separate',
            inheritedHardFileBytes=STREAM_BYTES,rawLogLogicalReservationBytes=RAW_BYTES,
            cleanupReservedBytes=CLEANUP_RESERVED_BYTES,perChildPairReservationBytes=2*STREAM_BYTES,
            compactEvidenceBytes=256*MIB,postgresDefaultWalSegmentBytes=16*MIB,
            fixtureFileAdmission=self.fixture_file_admission,
            fixtureRestriction='before foreground PG require initialized16MiB WAL and all initialfiles<=32MiB; frozen DDL-only fixture; all later data/evidence/log files subject to32MiB hard cap; larger files fail closed',
            hardVsMonitored='per-file logical cap hard; aggregate raw-log logical ceiling reserved before spawn; allocated bytes monitored at admission; filesystem metadata/PG data excluded',
            parentSigxfszIgnored=self.sigxfsz_ignored,
            signalContract='SIGXFSZ must already be ignored before hardcap and every admission; policy changes no handlers',
            prepared=self.prepared,installed=self.installed,currentReservedBytes=len(self.tokens)*2*STREAM_BYTES,
            highWaterReservedBytes=self.high_water_reserved,highWaterObservedBytes=self.high_water_observed)
