"""Staged private adapter; import launches nothing. Native integration NOT RUN."""
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
DEPENDENCIES = {
    "closed_dependencies/guardian.py": "24e3963ce7af07b6708ac7bd315e7f1d681186acb002bf934faa618d2f5caa47",
    "closed_dependencies/private_streams/streams.py": "af0646f267f6e0d91b2a21c60e02d8edc9566da165df13581acb2656bbaa44e4",
    "closed_dependencies/private_streams/closed_dependencies/diagnostics.py": "4c4248088591e64f95008758682967b6e1e39c645609a769497f06b613d53328",
}
PUBLIC_SQL = {
    "verify-private-policy.sql": "b55fa449b5857ce6aa57dc2e23ebaf20203fa2d603b1cbf2ad876b74c75a9ac9",
    "fixture-ownership-bootstrap.sql": "fcdc64fbe0a4b333794f7937fe8bf91345b5bdc0f67f80865140aa04bb25d81d",
    "fixture-ops.sql": "7d40761cc7f8eab1ab6a9d00a6a0274e220e16c7574a06711224b4fbeea19f39",
}
PUBLIC_STDOUT = {
    "verify-private-policy.sql": "",
    "fixture-ownership-bootstrap.sql": "\n",
    "fixture-ops.sql": "",
}
POSITIVE_SHA256 = "1fe715e2245f05b372cb2dd8904d3dee08aeed893ae75f8f367a996df1c375c8"
SOURCE_INPUTS = "artifacts/consumer-derivatives-v2-s5-positive-auth-preparation/b303aa4a-8c5d-4171-84b2-31857f1c238a/source-inputs.json"
SOURCE_INPUTS_SHA256 = "46f5eeb2f03de99be1d1f3827d3f57904be8fb540250b175cd79804a4f2eb230"


def _source_digest(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            size += len(chunk)
            if size > 64*1024**2:
                raise PrivateFailure()
            digest.update(chunk)
    return digest.hexdigest()


class PrivateFailure(RuntimeError):
    def __init__(self):
        super().__init__("private operation rejected")


def _load(name, relative):
    path = ROOT / relative
    if hashlib.sha256(path.read_bytes()).hexdigest() != DEPENDENCIES[relative]:
        raise PrivateFailure()
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


base = _load("_staged_private_guardian_base", "closed_dependencies/guardian.py")
streams = _load("_staged_private_guardian_streams", "closed_dependencies/private_streams/streams.py")


class SinkRouting:
    """Apply sink policy BEFORE the only process factory call.

    The direct return has no post-factory work before base._launch registers it.
    Fake backends may supply _factory for source-only tests.
    """
    def spawn(self, argv, *, cwd, env, stdout, stderr):
        self.require_owner()
        route = self.guardian._spawn_route
        if route is None or tuple(argv) != route[1]:
            raise PrivateFailure()
        if route[0] == "private":
            stdout = stderr = subprocess.PIPE
        elif route[0] in ("server", "utility"):
            stdout = stderr = subprocess.DEVNULL
        elif route[0] != "public":
            raise PrivateFailure()
        try:
            return self._factory(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=stdout, stderr=stderr, start_new_session=True,
                                 bufsize=0)
        except BaseException:
            pass
        # Outside the except suite: no raw exception context/cause is retained.
        raise PrivateFailure()


class PrivateNative(SinkRouting, base.Native):
    def __init__(self):
        self.guardian = None
        self._factory = subprocess.Popen


class RetainedHooks:
    __slots__ = ("guardian",)

    def __init__(self, guardian):
        self.guardian = guardian

    def __repr__(self):
        return "<RetainedHooks private>"

    def retains(self, record):
        return any(child is record for child in self.guardian.children)

    def reap_if_ready(self, record):
        g = self.guardian
        if not self.retains(record) or record.reaped:
            raise PrivateFailure()
        g.checkpoint()
        if g.backend.peek(record.handle) is None:
            return None
        if g.backend.other_live_group_members(record.handle):
            return None
        g._finish(record)  # Existing WNOWAIT/group-quiet/actual retained reap.
        return record.exit_code

    def request_stop(self, record):
        if not self.retains(record):
            raise PrivateFailure()
        if not record.reaped:
            self.guardian._stop(record)  # Original emergency deadline, no renewal.


@dataclass(frozen=True, slots=True)
class AppointmentResult:
    stage: str
    private_result: streams.StreamResult | None
    cleanup_proven: bool
    owner_qualification_eligible: bool
    full_s5_qualified: bool = False

    def evidence(self):
        return asdict(self)


class PrivateGuardian(base.Guardian):
    def __init__(self, work, tools, *, started, database="lomi_derivative_fixture",
                 backend=None, clock=base.time.monotonic, sleep=base.time.sleep,
                 signals=base.signal, run_id=None, log_policy=None, io_factory=None,
                 _test_terminal_hook=None):
        self._construction_complete = False
        self._spawn_route = None
        self._phase = "public"
        self._sources_admitted = False
        self._positive_started = False
        self._private_records = []
        self._private_result = None
        self._pipe_close_failed = False
        if database not in base.DATABASES[1:]:
            raise PrivateFailure()
        selected = backend if backend is not None else PrivateNative()
        if (not isinstance(selected, PrivateNative)
                and not (getattr(selected, "test_only", False) is True
                         and isinstance(selected, SinkRouting))):
            raise PrivateFailure()
        if io_factory is not None and isinstance(selected, base.Native):
            raise PrivateFailure()
        self.database = database
        self._io_factory = io_factory
        super().__init__(work, tools, started=started, backend=selected, clock=clock,
                         sleep=sleep, signals=signals, run_id=run_id,
                         log_policy=log_policy, _test_terminal_hook=_test_terminal_hook)
        selected.guardian = self
        self.env.update(dict(streams._diagnostics.PRIVATE_ENV_FIXED))
        self._construction_complete = True
        for name, expected in {**PUBLIC_SQL, "positive-auth.sql": POSITIVE_SHA256}.items():
            content = (ROOT / name).read_bytes()
            if hashlib.sha256(content).hexdigest() != expected:
                raise PrivateFailure()
            path = self.work / name
            with path.open("xb") as out:
                base.os.fchmod(out.fileno(), 0o600)
                out.write(content)

    def __repr__(self):
        return "<PrivateGuardian staged>"

    def _source(self, name, expected):
        path = self.work / name
        info = path.lstat()
        if (path.is_symlink() or path.resolve() != path or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != base.os.getuid()
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise PrivateFailure()
        return path

    def verify_source_admission(self, source_root):
        """Read-only source gate; never a same-database runtime comparison."""
        try:
            root = Path(source_root)
            if not root.is_absolute() or root.resolve() != root:
                raise PrivateFailure()
            manifest = root / SOURCE_INPUTS
            with manifest.open("rb") as stream:
                manifest_bytes = stream.read(65537)
            if (len(manifest_bytes) > 65536
                    or hashlib.sha256(manifest_bytes).hexdigest() != SOURCE_INPUTS_SHA256):
                raise PrivateFailure()
            pins = json.loads(manifest_bytes)["sha256"]
            if len(pins) != 17:
                raise PrivateFailure()
            for relative, expected in pins.items():
                path = root / relative
                if (path.resolve() != path or any(p.is_symlink() for p in (path, *path.parents))
                        or _source_digest(path) != expected):
                    raise PrivateFailure()
            self._sources_admitted = True
            return True
        except BaseException:
            self._phase = "failed"
            self.unqualified = True
        raise PrivateFailure()

    def _public_args(self, name):
        return tuple(str(x) for x in ("-X", "--no-password", "-qAt", "-h", self.work/"socket",
                     "-p", "55439", "-U", "e2_owner", "-v", "ON_ERROR_STOP=1", "-v",
                     "VERBOSITY=verbose", "-d", self.database, "-f", self.work/name))

    def _private_args(self):
        return (*streams._diagnostics.CLIENT_FLAGS, "-h", str(self.work/"socket"), "-p", "55439",
                "-U", "e2_owner", "-d", self.database, "--file", "positive-auth.sql")

    def _postgres_args(self):
        return (*super()._postgres_args(), *streams._diagnostics.SERVER_FLAGS)

    def _launch(self, name, args, *, cleanup=False, foreground=False):
        args = tuple(str(part) for part in args)
        route = None
        if name == "postgres" and foreground and args == self._postgres_args():
            route = "server"
        elif name == "psql":
            if self._phase == "private-launch" and args == self._private_args():
                self._source("positive-auth.sql", POSITIVE_SHA256)
                route = "private"
            elif self._phase == "public":
                for script, expected in PUBLIC_SQL.items():
                    if args == self._public_args(script):
                        self._source(script, expected)
                        route = "public"
                        break
        elif name == "initdb" and self._phase == "public" and args == tuple(str(x) for x in (
                "-D", self.work/"data", "-U", "e2_owner", "--auth=trust", "--no-locale", "-E", "UTF8")):
            route = "utility"
        elif name == "pg_ctl" and args in (
                ("-D", str(self.work/"data"), "status"),
                ("-D", str(self.work/"data"), "-m", "immediate", "-w", "-t", "20", "stop")):
            route = "utility"
        if route is None or self._spawn_route is not None:
            raise PrivateFailure()
        self._spawn_route = (route, (self.executable(name), *args))
        try:
            record = super()._launch(name, args, cleanup=cleanup, foreground=foreground)
            if route == "private":
                self._private_records.append(record)
            return record
        finally:
            self._spawn_route = None

    def _public_empty(self, name):
        if self._phase != "public" or name not in PUBLIC_SQL:
            raise PrivateFailure()
        path = self._source(name, PUBLIC_SQL[name])
        record = base.Guardian.psql(self, self.database, path, expected=(0,))
        output = base.Guardian.result(self, record, max_bytes=4096)
        self._source(name, PUBLIC_SQL[name])
        if (not record.reaped or not record.group_quiet or type(output.returncode) is not int
                or output.returncode != 0 or output.evidenceComplete is not True
                or output.stdout != PUBLIC_STDOUT[name] or output.stderr != ""
                # Base result normalizes newlines; its raw-byte hashes keep this
                # per-script contract exact (CR/CRLF cannot stand in for LF).
                or output.stdoutSha256 != hashlib.sha256(PUBLIC_STDOUT[name].encode("ascii")).hexdigest()
                or output.stderrSha256 != hashlib.sha256(b"").hexdigest()):
            raise PrivateFailure()
        return True

    def run_public_schema(self, name):
        try:
            if name == "verify-private-policy.sql":
                raise PrivateFailure()
            return self._public_empty(name)
        except BaseException:
            self._phase = "failed"
            self.unqualified = True
        raise PrivateFailure()

    def verify_private_policy(self):
        try:
            if not self._sources_admitted or not self.startup_confirmed:
                raise PrivateFailure()
            self.verify_pg_identity()
            self._public_empty("verify-private-policy.sql")
            self.checkpoint()
            self.verify_pg_identity()
        except BaseException:
            self._phase = "failed"
            self.unqualified = True
        else:
            self._phase = "private-ready"
            return True
        raise PrivateFailure()

    def launch_private_sql(self):
        if self._phase != "private-ready" or self._positive_started:
            raise PrivateFailure()
        self._positive_started = True
        self._phase = "private-launch"
        try:
            record = self._launch("psql", self._private_args())
            # No cancellation check or fallible pipe setup before registration.
            handle = record.handle
            io = (self._io_factory(record) if self._io_factory is not None else
                  streams.AnonymousPipeIO(handle.stdout.fileno(), handle.stderr.fileno()))
            end = min(self.clock()+60, self.started+840, self.qualification_deadline)
            result = streams.pump(RetainedHooks(self), record, io, streams.new_parser(),
                                  end=end, clock=self.clock,
                                  cancelled=lambda: bool(self.cancel.requested or self.qualification_expired
                                                         or self.evidence_errors))
            self._private_result = result
            if result.outcome != "stream-finished" or result.diagnostic.stage != "complete":
                self.unqualified = True
            self._phase = "private-finished"
            return result
        except BaseException:
            self.unqualified = True
            self._phase = "failed"
        raise PrivateFailure()

    def psql(self, *args, **kwargs):
        raise PrivateFailure()  # Public entry points must use the closed script registry.

    def run_node(self, *args, **kwargs):
        raise PrivateFailure()

    def tool_version(self, *args, **kwargs):
        raise PrivateFailure()

    def result(self, *args, **kwargs):
        raise PrivateFailure()  # Never expose raw private output through base.result.

    def cleanup(self):
        result = super().cleanup()
        # Only fixed failure identifiers survive the public base's cleanup report.
        self.evidence_errors[:] = ["private-operation-failed"] if self.evidence_errors else []
        result["evidenceErrors"] = list(self.evidence_errors)
        result["errors"] = ["private-cleanup-failed"] if result["errors"] else []
        return result

    def finish_owner(self):
        if not self._construction_complete:
            # Construction creates no child. Preserve partially prepared work;
            # no ownership proof/deletion is inferred from an incomplete object.
            sink = getattr(self, "_emergency_sink", None)
            if sink is not None:
                sink.close()
            return {"completed": False, "qualificationEligible": False}
        result = super().finish_owner()  # May retain the actual owner forever.
        for record in self.children:
            # Registration failure may leave a private record outside our list.
            for stream in (getattr(record.handle, "stdout", None), getattr(record.handle, "stderr", None)):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException:
                        self._pipe_close_failed = self.unqualified = True
        if self._pipe_close_failed:
            result["qualificationEligible"] = False
        return result


def run_appointment(work, tools, body, *, source_root=None, **options):
    """The only supported outer driver seam: finally always owns cleanup.

    body is trusted reviewed controller code, never data or credential output.
    An actual runtime appointment and independently verified postconditions are
    required separately; even a complete stream never qualifies full S5 here.
    """
    owner = PrivateGuardian.__new__(PrivateGuardian)
    owner._construction_complete = False
    private_result = None
    cleanup = {"completed": False, "qualificationEligible": False}
    stage = "private-failure"
    try:
        owner.__init__(work, tools, **options)
        owner.verify_source_admission(ROOT.parents[1] if source_root is None else source_root)
        owner.install()
        body(owner)
        private_result = owner._private_result
        if private_result is not None and private_result.diagnostic.stage == "complete":
            stage = "private-stream-complete"
    except BaseException:
        if hasattr(owner, "unqualified"):
            owner.unqualified = True
    finally:
        cleanup = owner.finish_owner()
    return AppointmentResult(stage, private_result, cleanup.get("completed") is True,
                             cleanup.get("qualificationEligible") is True)
