"""Source-only native probe proposal. Default/import starts no child."""
from pathlib import Path
import hashlib
import importlib.util
import json
import math
import os
import resource
import re
import signal
import stat
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
PROJECT = Path("/Users/woro/Documents/Lomi/lomi-remote")
SCOPE = "private-pipe-guc-six-cases-only"
CASES = ("valid", "malformed", "trailing", "cancel-writer", "eof-alive", "private-guc")
NODE_MODES = CASES[:-1]
ADAPTER_SHA256 = "40b5a1200e13fb6ee2ec0f0d418d548cdbb3d77dd2bdf5285616a51db00e66c8"
EMITTER_SHA256 = "a7256617b6694eda368cfb6b769017135dd3cadda450bf0644d45860dd7f0ffa"
DATABASE_SQL_SHA256 = "1e493aba4c4847ca11390bd5a61d49cda1a9058c9170dc6db024fc71435721d7"
TOOLS_SHA256 = "cae6f168162810bfb13ab47e8fc2dce0c900e7d0599cced8fdcf8d81f5e57ec6"
POLICY_SHA256 = "1d631ec27f30f7b969ed32ab4504300a8932123401b0d5713a65b3a84a53cb3e"
MIB = 1024**2
WORK_BYTES = 2*1024**3


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(65536):
            result.update(chunk)
    return result.hexdigest()


def read_json(path):
    with Path(path).open("rb") as stream:
        content = stream.read(MIB+1)
    if len(content) > MIB:
        raise RuntimeError("probe rejected")
    return json.loads(content)


def pinned(path, expected):
    path = Path(path)
    if (not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents))
            or digest(path) != expected):
        raise RuntimeError("probe rejected")
    return path


def load_module(name, path, expected):
    path = pinned(path, expected)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_adapter():
    return load_module("_private_pipe_probe_adapter",
                       HERE/"closed_dependencies/private_guardian_staging/private_guardian.py",
                       ADAPTER_SHA256)


def valid_admission(value, freeze_sha256):
    return (type(value) is dict and set(value) == {"scope", "freezeSha256", "rootReviewed"}
            and type(value["scope"]) is str and value["scope"] == SCOPE
            and type(value["freezeSha256"]) is str and value["freezeSha256"] == freeze_sha256
            and value["rootReviewed"] is True)


def status():
    return {"scope": SCOPE, "status": "PREPARED_NOT_EXECUTED",
            "cases": {case: "NOT_RUN" for case in CASES},
            "nativeAdmission": "NOT_GRANTED", "externalOwnerExit": "PENDING_ROOT_RECEIPT",
            "positiveSqlCallsExecuted": 0, "fullS5Qualified": False}


def guard(freeze, tools):
    for relative, expected in freeze["sourceSha256"].items():
        pinned(HERE/relative, expected)
    pinned(HERE/"tools.json", TOOLS_SHA256)
    pinned(PROJECT/tools["lockPath"], tools["lockSha256"])
    for name in ("python", "node"):
        pinned(tools[name+"Path"], tools[name+"Sha256"])
    if len(tools["postgresFiles"]) != 47:
        raise RuntimeError("probe rejected")
    for relative, expected in tools["postgresFiles"].items():
        pinned(PROJECT/tools["postgresRoot"]/relative, expected)
    stdlib = Path(tools["pythonPath"]).parent.parent/"lib/python3.14"
    pinned(stdlib/"subprocess.py", "6628ffdd65c093a6c08cae01ffe82877d3ced515aac9e7be0cff16512c30a7d9")
    pinned(stdlib/"selectors.py", "4b8a60cfbb619d080f87dffe1578372e56e8c0ac826f043224a154cf7b77606d")
    return {"sourcePinsVerified": len(freeze["sourceSha256"]), "acceptedToolPinsVerified": 49,
            "localStdlibPinsVerified": 2}


class ProbeClock:
    """Real monotonic time only; cancellation never extends the owner budget."""
    def __init__(self, outer_started, case_started, case, work_paths=()):
        self.outer_started, self.case_started, self.case = outer_started, case_started, case
        self.guardian = None
        self.work_end = case_started + (60 if case == "private-guc" else 5)
        self.actual_case_limit = 120 if case == "private-guc" else 15
        self.work_expired = self.wall_expired = self.aggregate_expired = False
        self.work_paths = work_paths
        self.next_scan = case_started
        self.resource_exceeded = False

    def __call__(self):
        now = time.monotonic()
        self.work_expired = self.work_expired or now >= self.work_end
        self.wall_expired = self.wall_expired or now-self.case_started >= self.actual_case_limit
        self.aggregate_expired = self.aggregate_expired or now-self.outer_started >= 300
        if now >= self.next_scan:
            self.next_scan = now+1
            try:
                self.resource_exceeded = self.resource_exceeded or allocated_bytes(self.work_paths) > WORK_BYTES
            except BaseException:
                self.resource_exceeded = True
        if self.guardian is not None and (self.work_expired or self.wall_expired
                                         or self.aggregate_expired or self.resource_exceeded):
            self.guardian.cancel.handle(signal.SIGALRM)
        return now


class ObservedPipeIO:
    """One exclusive consumer, fixed facts only; never retain raw read chunks."""
    def __init__(self, adapter, guardian, record, mode, inner):
        self.adapter, self.guardian, self.record = adapter, guardian, record
        self.mode, self.inner = mode, inner
        self.eof = [False, False]
        self.max_read = 0
        self.first_nonempty_live = self.cancel_latched = self.eof_both_live = False
        self.pipe_provenance = False

    def __repr__(self):
        return "<ObservedPipeIO private>"

    def start(self):
        self.inner.start()
        # Provenance is construction-based: pinned Popen+PIPE, not FIFO mode alone.
        if isinstance(self.guardian.backend, self.adapter.PrivateNative):
            streams = (self.record.handle.stdout, self.record.handle.stderr)
            fds = tuple(stream.fileno() for stream in streams)
            self.pipe_provenance = (
                pinned_native_factory(self.adapter, self.guardian)
                and type(self.inner) is self.adapter.streams.AnonymousPipeIO
                and self.inner._fds == fds
                and streams[0] is not streams[1] and fds[0] != fds[1]
                and all(stat.S_ISFIFO(os.fstat(fd).st_mode) and not os.get_blocking(fd)
                        and not os.get_inheritable(fd) for fd in fds))
            if not self.pipe_provenance:
                raise RuntimeError("probe rejected")

    def ready(self, timeout):
        return self.inner.ready(timeout)

    def read(self, stream):
        chunk = self.inner.read(stream)
        if type(chunk) is bytes:
            self.max_read = max(self.max_read, len(chunk))
            if self.mode == "cancel-writer" and chunk and not self.cancel_latched:
                self.first_nonempty_live = (not self.record.reaped
                    and self.guardian.backend.peek(self.record.handle) is None)
                self.guardian.cancel.handle(signal.SIGTERM)
                self.cancel_latched = True
        return chunk

    def retire(self, stream):
        self.inner.retire(stream)
        self.eof[stream] = True
        if all(self.eof) and not self.record.reaped:
            self.eof_both_live = self.guardian.backend.peek(self.record.handle) is None

    def close(self):
        self.inner.close()


def pinned_native_factory(adapter, guardian):
    return (type(guardian.backend) is adapter.PrivateNative
            and guardian.backend.guardian is guardian
            and guardian.backend._factory is adapter.subprocess.Popen
            and guardian.backend.spawn.__func__ is adapter.SinkRouting.spawn)


def probe_type(adapter):
    class ProbeGuardian(adapter.PrivateGuardian):
        """Closed test-only Node/setup seam; production allowlists stay frozen."""
        def __init__(self, *args, probe_io_builder=None, **kwargs):
            self._probe_adapter = adapter
            self._probe_mode = None
            self._probe_started = False
            self._observed = None
            self._probe_result = None
            self._probe_io_builder = probe_io_builder
            super().__init__(*args, **kwargs)
            self._probe_work_identity = file_identity(self.work, 0o700, directory=True)
            self._probe_socket_identity = file_identity(self.work/"socket", 0o700, directory=True)
            self._probe_marker_identity = file_identity(self.marker_path, 0o600)
            self._probe_marker_bytes = self.marker_bytes
            self._probe_run_id = self.run_id
            self._probe_case_started = self.clock()
            self._probe_stream_end = None
            self._probe_data_identity = None
            if probe_io_builder is not None and isinstance(self.backend, adapter.base.Native):
                raise adapter.PrivateFailure()
            for name, expected in (("emitter.cjs", EMITTER_SHA256),
                                   ("create-probe-database.sql", DATABASE_SQL_SHA256)):
                source = pinned(HERE/name, expected)
                with (self.work/name).open("xb") as out:
                    os.fchmod(out.fileno(), 0o600)
                    out.write(source.read_bytes())

        def _create_database_args(self):
            return tuple(str(x) for x in ("-X", "--no-password", "-qAt", "-h", self.work/"socket",
                         "-p", "55439", "-U", "e2_owner", "-v", "ON_ERROR_STOP=1", "-v",
                         "VERBOSITY=verbose", "-d", "postgres", "-f", self.work/"create-probe-database.sql"))

        def _launch(self, name, args, *, cleanup=False, foreground=False):
            args = tuple(str(part) for part in args)
            route = None
            if (name == "node" and self._probe_mode in NODE_MODES and not cleanup and not foreground
                    and args == (str(self.work/"emitter.cjs"), self._probe_mode)):
                self._source("emitter.cjs", EMITTER_SHA256)
                route = "private"
            elif (name == "psql" and self._phase == "public" and not cleanup and not foreground
                    and args == self._create_database_args()):
                self._source("create-probe-database.sql", DATABASE_SQL_SHA256)
                route = "public"
            if route is None:
                return super()._launch(name, args, cleanup=cleanup, foreground=foreground)
            if self._spawn_route is not None:
                raise adapter.PrivateFailure()
            self._spawn_route = (route, (self.executable(name), *args))
            try:
                # Exact frozen base registration; actual Popen returned untouched.
                return adapter.base.Guardian._launch(self, name, args, cleanup=cleanup, foreground=foreground)
            finally:
                self._spawn_route = None

        def create_probe_database(self):
            if self._phase != "public" or not self.startup_confirmed:
                raise adapter.PrivateFailure()
            path = self._source("create-probe-database.sql", DATABASE_SQL_SHA256)
            record = adapter.base.Guardian.psql(self, "postgres", path, expected=(0,))
            output = adapter.base.Guardian.result(self, record, max_bytes=4096)
            self._source("create-probe-database.sql", DATABASE_SQL_SHA256)
            empty = hashlib.sha256(b"").hexdigest()
            if (not record.reaped or not record.group_quiet or type(output.returncode) is not int
                    or output.returncode != 0 or output.evidenceComplete is not True
                    or output.stdout != "" or output.stderr != ""
                    or output.stdoutSha256 != empty or output.stderrSha256 != empty):
                raise adapter.PrivateFailure()

        def launch_probe(self, mode, end):
            if mode not in NODE_MODES or self._probe_started:
                raise adapter.PrivateFailure()
            self._probe_started = True
            self._probe_mode = mode
            try:
                record = self._launch("node", (str(self.work/"emitter.cjs"), mode))
                inner = (self._probe_io_builder(record) if self._probe_io_builder is not None else
                         adapter.streams.AnonymousPipeIO(record.handle.stdout.fileno(), record.handle.stderr.fileno()))
                self._observed = ObservedPipeIO(adapter, self, record, mode, inner)
                limit = min(end, self.clock()+60, self.started+840, self.qualification_deadline)
                self._probe_stream_end = limit
                self._probe_result = adapter.streams.pump(adapter.RetainedHooks(self), record,
                    self._observed, adapter.streams.new_parser(), end=limit, clock=self.clock,
                    cancelled=lambda: bool(self.cancel.requested or self.qualification_expired or self.evidence_errors))
                if self._probe_result.diagnostic.stage != "complete":
                    self.unqualified = True
                return self._probe_result
            finally:
                self._probe_mode = None
    return ProbeGuardian


def empty_metadata(guardian):
    return all(guardian._verified_log(path, identity).st_size == 0
               for record in guardian.children for path, identity in
               ((record.stdout, record.stdout_identity), (record.stderr, record.stderr_identity)))


def bounded_integer(value, low=0, high=2**64-1):
    if type(value) is not int or not low <= value <= high:
        raise RuntimeError("probe metadata rejected")
    return value


def finite_time(value):
    if type(value) not in (int, float) or not 0 <= value <= 10**12 or not math.isfinite(value):
        raise RuntimeError("probe metadata rejected")
    return value


def file_identity(path, mode, *, directory=False):
    info = path.lstat()
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or stat.S_IMODE(info.st_mode) != mode or info.st_uid != os.getuid()
            or not directory and info.st_nlink != 1):
        raise RuntimeError("probe metadata rejected")
    return (bounded_integer(info.st_dev), bounded_integer(info.st_ino),
            bounded_integer(info.st_uid), mode)


def identity_fields(identity):
    return dict(zip(("device", "inode", "uid", "mode"), identity))


def operation_metadata(guardian, case):
    records = []
    if not 1 <= len(guardian.children) <= 8:
        raise RuntimeError("probe metadata rejected")
    for ordinal, record in enumerate(guardian.children, 1):
        if type(record.argv) is not tuple or any(type(part) is not str for part in record.argv):
            raise RuntimeError("probe metadata rejected")
        operation = role = None
        args = record.argv[1:]
        name = record.name
        if type(name) is not str or name not in guardian.tools:
            raise RuntimeError("probe metadata rejected")
        if record.argv[0] != str(guardian.tools[name].path):
            raise RuntimeError("probe metadata rejected")
        if name == "node" and case in NODE_MODES and args == (str(guardian.work/"emitter.cjs"), case):
            operation, role = "node."+case, "node-emitter"
        elif name == "postgres" and args == guardian._postgres_args():
            operation, role = "postgres.foreground", "foreground-postgres"
        elif name == "initdb" and args == tuple(str(x) for x in ("-D", guardian.work/"data", "-U", "e2_owner",
                                                               "--auth=trust", "--no-locale", "-E", "UTF8")):
            operation, role = "initdb", "initdb-client"
        elif name == "pg_ctl":
            if args == ("-D", str(guardian.work/"data"), "status"):
                operation, role = "pg_ctl.status", "pgctl-client"
            elif args == ("-D", str(guardian.work/"data"), "-m", "immediate", "-w", "-t", "20", "stop"):
                operation, role = "pg_ctl.stop", "pgctl-client"
        elif name == "psql":
            if args == guardian._create_database_args():
                operation, role = "psql.create-probe-database", "psql-client"
            elif args == guardian._public_args("verify-private-policy.sql"):
                operation, role = "psql.verify-private-policy", "psql-client"
        if (operation is None or record.reaped is not True or record.group_quiet is not True
                or type(record.foreground) is not bool or type(record.forced) is not bool):
            raise RuntimeError("probe metadata rejected")
        records.append({"ordinal": ordinal, "operation": operation, "processRole": role,
                        "retainedPid": bounded_integer(record.handle.pid, 1, 2**31-1),
                        "exitCode": bounded_integer(record.exit_code, -255, 255),
                        "reaped": True, "groupQuiet": True,
                        "foreground": record.foreground, "forced": record.forced,
                        "ownershipObservation": "retained-group-quiet-at-owner-reap-only"})
    return records


def post_cleanup_metadata(guardian, case):
    if (guardian._emergency_sink.closed is not True or guardian.handlers_installed is not False
            or guardian.cleanup_result is None or guardian.cleanup_result.get("ownershipUnresolved") is not False):
        raise RuntimeError("probe metadata rejected")
    work = guardian.work
    if (not work.is_absolute() or work.resolve() != work
            or any(path.is_symlink() for path in (work, *work.parents))
            or file_identity(work, 0o700, directory=True) != guardian._probe_work_identity
            or file_identity(work/"socket", 0o700, directory=True) != guardian._probe_socket_identity
            or guardian.marker_path != work/"guardian-owned.json"
            or file_identity(guardian.marker_path, 0o600) != guardian._probe_marker_identity):
        raise RuntimeError("probe metadata rejected")
    run_id = guardian.run_id
    if (type(run_id) is not str or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", run_id) is None
            or run_id != guardian._probe_run_id or guardian.marker_bytes != guardian._probe_marker_bytes):
        raise RuntimeError("probe metadata rejected")
    marker = {"runId": run_id, "work": str(work), "data": str(work/"data"), "socket": str(work/"socket")}
    expected = (json.dumps(marker, sort_keys=True)+"\n").encode()
    if expected != guardian._probe_marker_bytes:
        raise RuntimeError("probe metadata rejected")
    marker_fd = os.open(guardian.marker_path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(marker_fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)) != guardian._probe_marker_identity
                or stream.read(2049) != expected):
            raise RuntimeError("probe metadata rejected")
    if guardian._probe_data_identity is not None:
        if file_identity(work/"data", 0o700, directory=True) != guardian._probe_data_identity:
            raise RuntimeError("probe metadata rejected")
    elif (work/"data").exists():
        raise RuntimeError("probe metadata rejected")
    try:
        (work/"data/postmaster.pid").lstat()
    except FileNotFoundError:
        pid_absent = True
    else:
        pid_absent = False
    socket_empty = not any((work/"socket").iterdir())
    if not pid_absent or not socket_empty:
        raise RuntimeError("probe metadata rejected")
    native_clock = type(guardian.clock) is ProbeClock
    original = finite_time(guardian.started)
    case_started = finite_time(guardian.clock.case_started if native_clock else guardian._probe_case_started)
    ended = finite_time(time.monotonic() if native_clock else guardian.clock())
    work_end = finite_time(min(case_started+(60 if case == "private-guc" else 5), original+840, original+300))
    stream_end = guardian._probe_stream_end
    if stream_end is not None:
        finite_time(stream_end)
        if not case_started <= stream_end <= work_end:
            raise RuntimeError("probe metadata rejected")
    if (not original <= case_started <= ended or ended > original+960
            or guardian.qualification_deadline != original+900 or guardian.emergency_deadline != original+960):
        raise RuntimeError("probe metadata rejected")
    native_locator = (work.parent == Path("/private/tmp")
                      and re.fullmatch(r"lpp-[a-z0-9_]{8}", work.name) is not None)
    if pinned_native_factory(guardian._probe_adapter, guardian) and not native_locator:
        raise RuntimeError("probe metadata rejected")
    operations = operation_metadata(guardian, case)
    if case != "private-guc" and (len(operations) != 1 or operations[0]["operation"] != "node."+case):
        raise RuntimeError("probe metadata rejected")
    return {"recordedAfterFinishOwner": True,
            "work": {"path": str(work), "identity": identity_fields(guardian._probe_work_identity),
                     "runId": run_id, "nativeLocator": native_locator,
                     "markerPath": str(guardian.marker_path), "markerIdentity": identity_fields(guardian._probe_marker_identity),
                     "markerSha256": hashlib.sha256(expected).hexdigest(),
                     "dataPath": str(work/"data"),
                     "dataIdentity": (identity_fields(guardian._probe_data_identity)
                                      if guardian._probe_data_identity is not None else None),
                     "postmasterPidPath": str(work/"data/postmaster.pid"), "postmasterPidAbsent": pid_absent,
                     "socketPath": str(work/"socket"), "socketIdentity": identity_fields(guardian._probe_socket_identity),
                     "socketEmpty": socket_empty},
            "timing": {"clockKind": "native-monotonic" if native_clock else "fake-injected",
                       "originalStarted": original, "originalWorkDeadline": original+840,
                       "qualificationDeadline": original+900, "emergencyDeadline": original+960,
                       "aggregateDeadline": original+300, "caseStarted": case_started, "caseEnded": ended,
                       "caseElapsedSeconds": ended-case_started, "caseWorkDeadline": work_end,
                       "streamDeadline": stream_end, "actualCaseLimitSeconds": 120 if case == "private-guc" else 15,
                       "actualCaseDeadline": case_started+(120 if case == "private-guc" else 15)},
            "operations": operations}


def closed_case_summary(case, guardian, cleanup, body_complete):
    stream = guardian._probe_result
    observed = guardian._observed
    facts = {"case": case, "bodyComplete": body_complete is True,
             "publicMetadata": post_cleanup_metadata(guardian, case),
             "cleanupProven": cleanup.get("completed") is True,
             "allRetainedReaped": all(record.reaped and record.group_quiet for record in guardian.children),
             "emptyMetadataLogs": empty_metadata(guardian),
             "originalDeadlinesPreserved": guardian.qualification_deadline == guardian.started+900
                 and guardian.emergency_deadline == guardian.started+960,
             "ownerQualificationEligible": cleanup.get("qualificationEligible") is True,
             "ownedWorkRetained": True,
             "positiveSqlCallsExecuted": 0, "fullS5Qualified": False}
    if case == "private-guc":
        facts.update(effectiveGucGate=guardian._phase == "private-ready",
                     serverDevnullFromPinnedFactory=(pinned_native_factory(guardian._probe_adapter, guardian)
                         and guardian.postgres is not None
                         and guardian.postgres.handle.stdout is None
                         and guardian.postgres.handle.stderr is None),
                     normalPostmasterExit=cleanup.get("postmasterNormalExit") is True,
                     statusAbsent=cleanup.get("pgCtlStatusAbsent") is True,
                     pidAbsent=cleanup.get("postmasterPidAbsent") is True,
                     socketEmpty=cleanup.get("socketDirectoryEmpty") is True)
    else:
        facts.update(stream=(stream.evidence() if stream is not None else None),
                     anonymousExclusiveProvenance=observed.pipe_provenance if observed else False,
                     readBound256=observed.max_read <= 256 if observed else False,
                     firstNonemptyReadWhileLive=observed.first_nonempty_live if observed else False,
                     cancellationLatchedAfterRead=observed.cancel_latched if observed else False,
                     bothEofWhileChildLive=observed.eof_both_live if observed else False)
    return facts


def case_passes(facts, *, require_native_provenance=True):
    if not all(facts.get(key) is True for key in ("bodyComplete", "cleanupProven", "allRetainedReaped",
                                                "emptyMetadataLogs", "originalDeadlinesPreserved")):
        return False
    case = facts["case"]
    if facts.get("ownerQualificationEligible") is not (case in ("valid", "private-guc")):
        return False
    metadata = facts.get("publicMetadata")
    if type(metadata) is not dict or metadata.get("recordedAfterFinishOwner") is not True:
        return False
    if require_native_provenance and (metadata["work"]["nativeLocator"] is not True
                                      or metadata["timing"]["clockKind"] != "native-monotonic"):
        return False
    if case == "private-guc":
        return ([(r["operation"], r["exitCode"]) for r in metadata["operations"]] ==
                [("initdb", 0), ("postgres.foreground", 0), ("pg_ctl.status", 0),
                 ("psql.create-probe-database", 0), ("psql.verify-private-policy", 0),
                 ("pg_ctl.stop", 0), ("pg_ctl.status", 3)]
                and all(facts.get(key) is True for key in
                   ("effectiveGucGate", "normalPostmasterExit", "statusAbsent", "pidAbsent", "socketEmpty"))
                and (not require_native_provenance or facts.get("serverDevnullFromPinnedFactory") is True))
    if facts.get("readBound256") is not True or (require_native_provenance and facts.get("anonymousExclusiveProvenance") is not True):
        return False
    stream = facts.get("stream")
    if type(stream) is not dict:
        return False
    diagnostic = stream["diagnostic"]
    if case == "valid":
        return (stream["outcome"] == "stream-finished" and diagnostic["stage"] == "complete"
                and diagnostic["count"] == 13 and diagnostic["exit"] == 0
                and stream["stdout_eof"] is True and stream["stderr_eof"] is True and stream["child_reaped"] is True)
    if diagnostic["stage"] != "generic-failure" or diagnostic["state"] is not None or diagnostic["count"] != 0:
        return False
    if case in ("malformed", "trailing"):
        return stream["outcome"] == "protocol-failure"
    if case == "cancel-writer":
        return (stream["outcome"] == "cancelled" and facts["firstNonemptyReadWhileLive"] is True
                and facts["cancellationLatchedAfterRead"] is True)
    if case == "eof-alive":
        return (stream["outcome"] == "deadline" and diagnostic["deadline"] is True
                and facts["bothEofWhileChildLive"] is True and stream["stdout_eof"] is True
                and stream["stderr_eof"] is True and stream["child_reaped"] is False)
    return False


def execute_case(case, guardian, *, source_root, end, admit_data=lambda g: None):
    """Publication only after finally has completed the retained owner's exit guard."""
    cleanup = {"completed": False}
    body_complete = False
    try:
        guardian.verify_source_admission(source_root)
        guardian.install()
        if case == "private-guc":
            guardian.initialize()
            guardian._probe_data_identity = file_identity(guardian.work/"data", 0o700, directory=True)
            admit_data(guardian)
            guardian.start_postgres()
            guardian.wait_startup()
            guardian.create_probe_database()
            guardian.verify_private_policy()
        else:
            guardian.launch_probe(case, end)
        body_complete = True
    except BaseException:
        guardian.unqualified = True
    finally:
        cleanup = guardian.finish_owner()
    try:
        return closed_case_summary(case, guardian, cleanup, body_complete)
    except BaseException:
        return {"case": case, "bodyComplete": False, "cleanupProven": cleanup.get("completed") is True,
                "metadataStatus": "rejected", "fullS5Qualified": False, "positiveSqlCallsExecuted": 0}


def allocated_bytes(paths):
    total = 0
    for work in paths:
        for path in work.rglob("*"):
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue  # A concurrently renamed initdb/PG file is no longer charged here.
            if not stat.S_ISDIR(info.st_mode):
                total += max(info.st_size, info.st_blocks*512)
    return total


def construct_owner(probe, work, executables, *, started, clock, policy=None, **test_options):
    owner = probe.__new__(probe)
    owner._construction_complete = False
    try:
        owner.__init__(work, executables, started=started, clock=clock,
                       log_policy=policy, **test_options)
        clock.guardian = owner
        return owner
    except BaseException:
        owner.finish_owner()
    raise RuntimeError("probe rejected")


def private_parent_environment():
    allowed = {"HOME", "TMPDIR", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "__CF_USER_TEXT_ENCODING"}
    if set(os.environ)-allowed or os.environ.get("PATH") != "/usr/bin:/bin":
        raise RuntimeError("probe rejected")
    if "__CF_USER_TEXT_ENCODING" in os.environ:
        marker = os.environ["__CF_USER_TEXT_ENCODING"]
        if type(marker) is not str or marker != f"0x{os.getuid():X}:0x0:0x0":
            raise RuntimeError("probe rejected")
    for key, values in (("LANG", ("C",)), ("LC_ALL", ("C",)),
                        ("LC_CTYPE", ("C", "C.UTF-8", "UTF-8")), ("TZ", ("UTC",))):
        if key in os.environ and os.environ[key] not in values:
            raise RuntimeError("probe rejected")
    for key in ("HOME", "TMPDIR"):
        path = Path(os.environ.get(key, ""))
        info = path.lstat()
        if (not path.is_absolute() or path.resolve() != path or path.is_symlink()
                or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_uid != os.getuid()):
            raise RuntimeError("probe rejected")


def native(admission_path):
    outer_started = time.monotonic()
    freeze = read_json(HERE/"freeze.json")
    freeze_hash = digest(HERE/"freeze.json")
    if not valid_admission(read_json(admission_path), freeze_hash):
        raise RuntimeError("probe rejected")
    tools = read_json(HERE/"tools.json")
    if (sys.executable != tools["pythonPath"] or sys.flags.isolated != 1
            or sys.flags.no_site != 1 or sys.dont_write_bytecode is not True):
        raise RuntimeError("probe rejected")
    private_parent_environment()
    before = guard(freeze, tools)
    adapter = load_adapter()
    policy_module = load_module("_private_probe_resource_policy", HERE/"closed_dependencies/resource_policy.py", POLICY_SHA256)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        raise RuntimeError("probe rejected")
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    probe = probe_type(adapter)
    executables = {name: adapter.base.Executable(PROJECT/tools["postgresRoot"]/"Contents/Versions/18/bin"/name,
        tools["postgresFiles"]["Contents/Versions/18/bin/"+name]) for name in ("initdb", "postgres", "psql", "pg_ctl")}
    executables["node"] = adapter.base.Executable(Path(tools["nodePath"]), tools["nodeSha256"])
    results = []
    works = []
    for case in CASES:
        if time.monotonic()-outer_started >= 300 or allocated_bytes(works) >= WORK_BYTES:
            raise RuntimeError("probe rejected")
        fs = os.statvfs("/private/tmp")
        if fs.f_bavail*fs.f_frsize < WORK_BYTES:
            raise RuntimeError("probe rejected")
        work = Path(tempfile.mkdtemp(prefix="lpp-", dir="/private/tmp")).resolve()
        os.chmod(work, 0o700)
        works.append(work)
        if len(os.fsencode(work/"socket/.s.PGSQL.55439")) >= 104:
            raise RuntimeError("probe rejected")
        case_started = time.monotonic()
        clock = ProbeClock(outer_started, case_started, case, works)
        policy = policy_module.ResourcePolicy()
        owner = construct_owner(probe, work, executables, started=outer_started, clock=clock, policy=policy)
        end = min(clock.work_end, outer_started+300, outer_started+840)
        if case == "eof-alive":
            end = min(end, case_started+2)
        facts = execute_case(case, owner, source_root=PROJECT, end=end,
                             admit_data=lambda g: policy.admit_fixture_files(g.work/"data"))
        elapsed = time.monotonic()-case_started
        facts["actualCaseWithinLimit"] = elapsed <= clock.actual_case_limit
        facts["aggregateWithin300"] = time.monotonic()-outer_started <= 300
        facts["monitoredWorkWithin2GiB"] = not clock.resource_exceeded and allocated_bytes(works) <= WORK_BYTES
        facts["hardFileCap32MiB"] = resource.getrlimit(resource.RLIMIT_FSIZE) == (32*MIB, 32*MIB)
        facts["passed"] = (case_passes(facts) and facts["actualCaseWithinLimit"]
                            and facts["aggregateWithin300"] and facts["monitoredWorkWithin2GiB"]
                            and facts["hardFileCap32MiB"])
        results.append(facts)
        if facts["passed"] is not True:
            break
    after = guard(freeze, tools)
    if digest(HERE/"freeze.json") != freeze_hash:
        raise RuntimeError("probe rejected")
    return {"scope": SCOPE, "status": "NATIVE_PROBES_COMPLETE", "cases": results,
            "allSixPassed": len(results) == 6 and all(item["passed"] is True for item in results),
            "sourceToolPinsBeforeAfterEqual": before == after,
            "externalOwnerExit": "PENDING_ROOT_RECEIPT", "positiveSqlCallsExecuted": 0,
            "credentialsCreated": False, "fullS5Qualified": False}


def main(argv):
    if not argv:
        return status(), 0
    if len(argv) != 2 or argv[0] != "--native-admission":
        return {"scope": SCOPE, "status": "REJECTED", "fullS5Qualified": False}, 1
    try:
        result = native(argv[1])
        return result, 0 if result["allSixPassed"] else 1
    except BaseException:
        return {"scope": SCOPE, "status": "FAILED", "fullS5Qualified": False,
                "externalOwnerExit": "PENDING_ROOT_RECEIPT"}, 1


if __name__ == "__main__":
    result, code = main(sys.argv[1:])
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(code)
