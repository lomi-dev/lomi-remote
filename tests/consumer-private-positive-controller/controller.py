"""Eleven positive-auth checks: staged SOURCE ONLY; default starts no child."""
from pathlib import Path
import hashlib
import json
import math
import os
import re
import resource
import signal
import stat
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
PROJECT=Path("/Users/woro/Documents/Lomi/lomi-remote")
SCOPE="private-positive-auth-eleven-only"
TRUSTED_ADMISSION_UID=0
ADMISSION_ROOT=Path("/private/var/db/lomi/consumer-private-eleven-root-admission")
SIX_RECEIPT_PATH="artifacts/consumer-private-six-root-result/49c72976-94a3-4ee4-9f53-d639f2ec5fba/receipt.json"
SIX_RECEIPT_SHA="93958dc25b28fd141458fccce097c6b3a0d62ca549a2ad061f04fa18d5685536"
CTAS_RECEIPT_PATH="artifacts/consumer-ctas4-root-result/2b1beb03-4ba8-41db-b211-414dfb7cbf1c/partial-result.json"
CTAS_RECEIPT_SHA="5db788dcd2c2519a65ef94da3470441e8d3f4b3c11d7d1579548afdbc9ae6e1d"
MIB=1024**2
WORK_LIMIT=2*1024**3
MAX_PUBLIC=MIB
ADAPTER_SHA="40b5a1200e13fb6ee2ec0f0d418d548cdbb3d77dd2bdf5285616a51db00e66c8"
AUTHORITY_SHA="478790888adf7dea8a9ef4a06e5054eda79b2851ff9f9544699dcd831458d8f2"
POLICY_SHA="1d631ec27f30f7b969ed32ab4504300a8932123401b0d5713a65b3a84a53cb3e"
WRAPPER_SHA="993372a18c72c6649c4e8a14ce4a869828727a0a85b316424c496cb9ae9d8110"
REGISTRY_SHA="2cfde1802336b918095ab7bc03829b0802f741d6a85e3ab7801b27499a488ae2"
REFERENCE_SHA={"old":{"catalog":"22b8d94c84e4961d649c71b3be32eeb28d08b0a892f2630c3578504d1d9fab3d",
                      "metadata":"f1053e915053ca5d11ffeff72442ee59792fdc0fc5543916e5003f73c593b63a"},
               "new":{"catalog":"361b3d3b663b873f907685f5b6b33311efef94b2a432b8a2af44668dba16caa1",
                      "metadata":"6b310ec492a2871f9c2d240032d8eb5881114c0f0da489ba2c9c56e33e7f2570"}}
EMPTY_SHA=hashlib.sha256(b"").hexdigest()


class Rejected(RuntimeError):
    def __init__(self):super().__init__("private appointment rejected")


def digest(path):
    result=hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk:=stream.read(65536):result.update(chunk)
    return result.hexdigest()


def protected_path(path, *, uid=0, boundary=Path("/")):
    """Admit one regular file or directory in a trusted, read-only tree."""
    path=Path(path);boundary=Path(boundary)
    if not path.is_absolute() or not boundary.is_absolute():raise Rejected()
    if any(part.is_symlink() for part in (path,*path.parents)):raise Rejected()
    try:relative=path.relative_to(boundary)
    except ValueError:raise Rejected() from None
    chain=[boundary]
    current=boundary
    for part in relative.parts:
        current=current/part;chain.append(current)
    for index,item in enumerate(chain):
        info=item.lstat()
        if info.st_uid!=uid or info.st_mode & 0o222:raise Rejected()
        if index<len(chain)-1 and not stat.S_ISDIR(info.st_mode):raise Rejected()
        if index==len(chain)-1 and not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise Rejected()
    return path


def protected_runtime_modules():
    """Admit already-loaded Python code from the protected root closure."""
    for module in tuple(sys.modules.values()):
        path=getattr(module,"__file__",None)
        if type(path) is str and path.startswith("/"):
            protected_path(Path(path))


def pinned(path, expected):
    path=Path(path)
    if not path.is_absolute() or any(p.is_symlink() for p in (path,*path.parents)) or digest(path)!=expected:
        raise Rejected()
    return path


def read_json(path):
    with Path(path).open("rb") as stream:raw=stream.read(4*MIB+1)
    if len(raw)>4*MIB:raise Rejected()
    return json.loads(raw)


def load(name,path,expected):
    # Read once, verify those bytes, then execute those same bytes. A path
    # replacement between hashing and import can no longer change the module.
    path=pinned(path,expected)
    raw=path.read_bytes()
    return load_verified_source(name,path,raw,expected)


def load_verified_source(name,path,raw,expected):
    if hashlib.sha256(raw).hexdigest()!=expected:raise Rejected()
    module=type(sys)(name);module.__file__=str(path);module.__package__=""
    sys.modules[name]=module
    try:exec(compile(raw,str(path),"exec"),module.__dict__)
    except BaseException:
        sys.modules.pop(name,None);raise
    return module


def private_environment():
    allowed={"HOME","TMPDIR","PATH","LANG","LC_ALL","LC_CTYPE","TZ","__CF_USER_TEXT_ENCODING"}
    if set(os.environ)-allowed or os.environ.get("PATH")!="/usr/bin:/bin":raise Rejected()
    if "__CF_USER_TEXT_ENCODING" in os.environ:
        value=os.environ["__CF_USER_TEXT_ENCODING"]
        if type(value) is not str or value!=f"0x{os.getuid():X}:0x0:0x0":raise Rejected()
    for key,values in (("LANG",("C",)),("LC_ALL",("C",)),("LC_CTYPE",("C","C.UTF-8","UTF-8")),("TZ",("UTC",))):
        if key in os.environ and os.environ[key] not in values:raise Rejected()
    for key in ("HOME","TMPDIR"):
        path=Path(os.environ.get(key,""));info=path.lstat()
        if (not path.is_absolute() or path.resolve()!=path or path.is_symlink()
                or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=os.getuid()):raise Rejected()


def verify_inputs(freeze,tools,*,require_root=False):
    if require_root:
        protected_path(HERE);protected_path(PROJECT)
        protected_path(HERE/"controller.py");protected_path(HERE/"freeze.json");protected_path(HERE/"tools.json")
        protected_path(HERE/"source-inputs.json")
    def admit(path,pin):
        if require_root:protected_path(path)
        pinned(path,pin)
    for name,pin in freeze["sourceSha256"].items():admit(HERE/name,pin)
    sources=read_json(HERE/"source-inputs.json")["sha256"]
    for name,pin in sources.items():admit(PROJECT/name,pin)
    admit(PROJECT/tools["lockPath"],tools["lockSha256"])
    for name in ("python","node"):admit(tools[name+"Path"],tools[name+"Sha256"])
    if len(tools["postgresFiles"])!=47:raise Rejected()
    for name,pin in tools["postgresFiles"].items():admit(PROJECT/tools["postgresRoot"]/name,pin)
    stdlib=Path(tools["pythonPath"]).parent.parent/"lib/python3.14"
    admit(stdlib/"subprocess.py","6628ffdd65c093a6c08cae01ffe82877d3ced515aac9e7be0cff16512c30a7d9")
    admit(stdlib/"selectors.py","4b8a60cfbb619d080f87dffe1578372e56e8c0ac826f043224a154cf7b77606d")
    return {"sourcePins":len(freeze["sourceSha256"]),"originalAuthorityPins":len(sources),"acceptedToolPins":49,"localStdlibPins":2}


def allocated(work):
    total=0
    for path in work.rglob("*"):
        try:info=path.lstat()
        except FileNotFoundError:continue
        if not stat.S_ISDIR(info.st_mode):total+=max(info.st_size,info.st_blocks*512)
    return total


class AppointmentClock:
    """Original monotonic time and monitored work limit; no exception payload."""
    def __init__(self,started,work):
        self.started,self.work,self.guardian=started,work,None
        self.next_scan=started;self.resource_failed=False
    def __call__(self):
        now=time.monotonic()
        if now>=self.next_scan:
            self.next_scan=now+1
            try:
                if allocated(self.work)>WORK_LIMIT:self.resource_failed=True
            except BaseException:self.resource_failed=True
        if self.guardian is not None and ((now>=self.started+840 and not self.guardian.cleanup_started) or self.resource_failed):
            self.guardian.unqualified=True;self.guardian.cancel.handle(signal.SIGALRM)
        return now


class PrivatePipeConsumer:
    """Exclusive pinned binary pipe adapter; fixed facts, no retained chunks."""
    def __init__(self,adapter,owner,record,inner):
        self.adapter,self.owner,self.record,self.inner=adapter,owner,record,inner
        self.provenance=False;self.max_read=0
    def __repr__(self):return "<PrivatePipeConsumer private>"
    def start(self):
        self.inner.start()
        a,g=self.adapter,self.owner
        if isinstance(g.backend,a.base.Native):
            streams=(self.record.handle.stdout,self.record.handle.stderr)
            fds=tuple(stream.fileno() for stream in streams)
            self.provenance=(type(g.backend) is a.PrivateNative and g.backend.guardian is g
                and g.backend._factory is a.subprocess.Popen and g.backend.spawn.__func__ is a.SinkRouting.spawn
                and type(self.inner) is a.streams.AnonymousPipeIO and self.inner._fds==fds
                and streams[0] is not streams[1] and fds[0]!=fds[1]
                and all(stat.S_ISFIFO(os.fstat(fd).st_mode) and not os.get_blocking(fd)
                        and not os.get_inheritable(fd) for fd in fds))
            if not self.provenance:raise Rejected()
    def ready(self,timeout):return self.inner.ready(timeout)
    def read(self,stream):
        chunk=self.inner.read(stream)
        if type(chunk) is bytes:
            if len(chunk)>256:raise Rejected()
            self.max_read=max(self.max_read,len(chunk))
        return chunk
    def retire(self,stream):self.inner.retire(stream)
    def close(self):self.inner.close()


def guardian_type(adapter):
    class PositiveGuardian(adapter.PrivateGuardian):
        """Narrow new registry/wrapper subclass; frozen production bytes intact."""
        def __init__(self,*args,registry=None,source_pins=None,authority=None,references=None,**kwargs):
            self._disposal_boundary=False
            native=kwargs.get("backend") is None or isinstance(kwargs.get("backend"),adapter.base.Native)
            if native:
                # Native construction accepts no caller SQL registry/hash or
                # authority override. Injection is isolated to marked fakes.
                if any(value is not None for value in (registry,source_pins,authority,references)):raise Rejected()
                registry=read_json(pinned(HERE/"public-registry.json",REGISTRY_SHA))
                source_pins={"private-positive-driver.sql":WRAPPER_SHA}
                authority=load("_positive_native_authority",HERE/"closed_dependencies/authority.py",AUTHORITY_SHA)
                references={state:{kind:read_json(pinned(HERE/f"reference-{state}-{kind}.json",pin))
                                   for kind,pin in kinds.items()} for state,kinds in REFERENCE_SHA.items()}
            self._registry=registry;self._local_pins=source_pins
            self._positive_adapter=adapter;self._consumer=None
            self._authority=authority;self._references=references
            self._schedule_index=0;self._active_public=None;self._public_records=[]
            self._public_receipts=[];self._pending_catalog=None;self._guc_retired=False
            self._disposal_boundary=False
            super().__init__(*args,**kwargs)
            if len(registry["orderedSchedule"])!=134 or len(registry["sqlSha256"])!=46:raise Rejected()
            for name,pin in registry["sqlSha256"].items():
                raw=pinned(HERE/"sql"/name,pin).read_bytes()
                with (self.work/("public-"+name)).open("xb") as out:
                    os.fchmod(out.fileno(),0o600);out.write(raw)
            raw=pinned(HERE/"private-positive-driver.sql",source_pins["private-positive-driver.sql"]).read_bytes()
            with (self.work/"private-positive-driver.sql").open("xb") as out:
                os.fchmod(out.fileno(),0o600);out.write(raw)

        def _full_public_args(self,entry):
            return tuple(str(x) for x in ("-X","--no-password","-qAt","-h",self.work/"socket","-p","55439",
                "-U","e2_owner","-v","ON_ERROR_STOP=1","-v","VERBOSITY=verbose","-d",entry["database"],
                "-f",self.work/("public-"+entry["script"])))

        def _private_args(self):
            return (*adapter.streams._diagnostics.CLIENT_FLAGS,"-h",str(self.work/"socket"),"-p","55439",
                    "-U","e2_owner","-d",self.database,"--file","private-positive-driver.sql")

        def _launch(self,name,args,*,cleanup=False,foreground=False):
            args=tuple(str(x) for x in args);route=None
            if name=="psql":
                if (self._phase=="public" and self._active_public is not None and not cleanup and not foreground
                        and args==self._full_public_args(self._active_public)):
                    entry=self._registry["orderedSchedule"][self._schedule_index]
                    if entry is not self._active_public:raise Rejected()
                    self._source("public-"+entry["script"],self._registry["sqlSha256"][entry["script"]]);route="public"
                elif (self._phase=="private-launch" and not cleanup and not foreground and args==self._private_args()):
                    self._source("private-positive-driver.sql",self._local_pins["private-positive-driver.sql"])
                    self._source("positive-auth.sql",adapter.POSITIVE_SHA256);route="private"
                elif (self._phase=="public" and self._schedule_index==134 and self._pending_catalog is None
                      and self.public_logs_retired() and args==self._public_args("verify-private-policy.sql")):
                    return super()._launch(name,args,cleanup=cleanup,foreground=foreground)
                else:raise Rejected()
            if route is None:return super()._launch(name,args,cleanup=cleanup,foreground=foreground)
            if self._spawn_route is not None:raise Rejected()
            self._spawn_route=(route,(self.executable(name),*args))
            try:
                # Actual handle returns directly to frozen retained registration.
                record=adapter.base.Guardian._launch(self,name,args,cleanup=cleanup,foreground=foreground)
                if route=="private":self._private_records.append(record)
                else:self._public_records.append(record)
                return record
            finally:self._spawn_route=None

        def run_public_schema(self,*args,**kwargs):raise Rejected()

        def public_logs_retired(self):
            return (len(self._public_records)==self._schedule_index
                    and all(record.retired is True and record.reaped is True and record.group_quiet is True
                            and not record.stdout.exists() and not record.stderr.exists() for record in self._public_records))

        def run_public_schedule(self):
            if self._phase!="public" or self._schedule_index!=0 or not self._sources_admitted:raise Rejected()
            try:
                for entry in self._registry["orderedSchedule"]:
                    self._active_public=entry
                    path=self._source("public-"+entry["script"],self._registry["sqlSha256"][entry["script"]])
                    record=adapter.base.Guardian.psql(self,entry["database"],path,expected=(0,))
                    result=adapter.base.Guardian.result(self,record,max_bytes=MAX_PUBLIC)
                    if (type(result.returncode) is not int or result.returncode!=0 or result.evidenceComplete is not True
                            or record.reaped is not True or record.group_quiet is not True):raise Rejected()
                    self._source("public-"+entry["script"],self._registry["sqlSha256"][entry["script"]])
                    equality=False
                    if entry["kind"]=="catalog":
                        self._pending_catalog=self._authority.parse_catalog(result.stdout)
                    elif entry["kind"]=="metadata":
                        metadata=self._authority.parse_catalog(result.stdout)
                        expected=self._references[entry["referenceState"]]
                        self._authority.reject_authority_drift(self._pending_catalog)
                        self._authority.reject_authority_drift(metadata)
                        if (self._authority.canonical(metadata)!=self._authority.canonical(expected["metadata"])
                                or self._authority.canonical(self._pending_catalog,self._authority.protected_relation_map(metadata))
                                !=self._authority.canonical(expected["catalog"],self._authority.protected_relation_map(expected["metadata"]))):raise Rejected()
                        self._pending_catalog=None;equality=True
                    if adapter.base.Guardian.retire_result(self,record,stdout_sha256=result.stdoutSha256,
                                                           stderr_sha256=result.stderrSha256) is not True:raise Rejected()
                    if not record.retired or record.stdout.exists() or record.stderr.exists():raise Rejected()
                    self._public_receipts.append({"ordinal":self._schedule_index+1,"script":entry["script"],
                        "sourceSha256":self._registry["sqlSha256"][entry["script"]],"retainedExit0":True,
                        "originalLogInodesAndDigestsVerifiedRetired":True,"independentReferencePairCompared":equality})
                    self._schedule_index+=1;self._active_public=None
                    del result
                if not self.public_logs_retired() or self._pending_catalog is not None:raise Rejected()
                return True
            except BaseException:
                self._pending_catalog=None;self._active_public=None;self._phase="failed";self.unqualified=True
            raise Rejected()

        def _public_empty(self,name):
            if name!="verify-private-policy.sql" or self._schedule_index!=134 or not self.public_logs_retired():raise Rejected()
            result=super()._public_empty(name)
            record=self.children[-1]
            if adapter.base.Guardian.retire_result(self,record,stdout_sha256=EMPTY_SHA,stderr_sha256=EMPTY_SHA) is not True:raise Rejected()
            self._guc_retired=True
            return result

        def launch_private_sql(self):
            if not self.public_logs_retired() or not self._guc_retired or self._pending_catalog is not None:raise Rejected()
            if not all_logs_empty_or_retired(self):raise Rejected()
            if self._phase!="private-ready" or self._positive_started:raise Rejected()
            self._positive_started=True;self._phase="private-launch"
            try:
                record=self._launch("psql",self._private_args())
                # No cancellation checkpoint or fallible pipe setup precedes
                # frozen base registration of the actual returned handle.
                inner=(self._io_factory(record) if self._io_factory is not None else
                       adapter.streams.AnonymousPipeIO(record.handle.stdout.fileno(),record.handle.stderr.fileno()))
                consumer=PrivatePipeConsumer(adapter,self,record,inner);self._consumer=consumer
                result=adapter.streams.pump(adapter.RetainedHooks(self),record,consumer,adapter.streams.new_parser(),
                    end=min(self.clock()+60,self.started+840,self.qualification_deadline),clock=self.clock,
                    cancelled=lambda: bool(self.cancel.requested or self.qualification_expired or self.evidence_errors))
                self._private_result=result;self._phase="private-finished"
                if result.outcome!="stream-finished" or result.diagnostic.stage!="complete":self.unqualified=True
                return result
            except BaseException:self.unqualified=True;self._phase="failed"
            raise Rejected()

        def finish_owner(self):
            if self._disposal_boundary:raise Rejected()
            return super().finish_owner()

        def cleanup(self):
            if self._disposal_boundary:raise Rejected()
            return super().cleanup()

    return PositiveGuardian


def all_logs_empty_or_retired(owner):
    for record in owner.children:
        if record.evidence_fallback:return False
        if record.retired:
            if record.stdout.exists() or record.stderr.exists():return False
        else:
            for path,identity in ((record.stdout,record.stdout_identity),(record.stderr,record.stderr_identity)):
                if owner._verified_log(path,identity).st_size!=0:return False
    return True


def retained_metadata(owner):
    if not 1<=len(owner.children)<=144:raise Rejected()
    output=[]
    for ordinal,record in enumerate(owner.children,1):
        if (record.reaped is not True or record.group_quiet is not True or type(record.exit_code) is not int
                or not -255<=record.exit_code<=255 or type(record.handle.pid) is not int
                or not 0<record.handle.pid<2**31):raise Rejected()
        if (type(record.argv) is not tuple or any(type(part) is not str for part in record.argv)
                or record.name not in owner.tools or record.argv[0]!=str(owner.tools[record.name].path)):raise Rejected()
        args=record.argv[1:]
        role={"postgres":"foreground-postgres","initdb":"initdb-client","pg_ctl":"pgctl-client","psql":"psql-client"}.get(record.name)
        if role is None:raise Rejected()
        operation=record.name
        if record.name=="psql":
            if args==owner._private_args():operation="private-positive-wrapper"
            elif args==owner._public_args("verify-private-policy.sql"):operation="verify-private-policy"
            else:
                indices=[i for i,child in enumerate(owner._public_records) if child is record]
                if len(indices)!=1:raise Rejected()
                entry=owner._registry["orderedSchedule"][indices[0]]
                if args!=owner._full_public_args(entry):raise Rejected()
                operation=entry["script"]
        elif record.name=="pg_ctl":
            if args==("-D",str(owner.work/"data"),"status"):operation="pg_ctl.status"
            elif args==("-D",str(owner.work/"data"),"-m","immediate","-w","-t","20","stop"):operation="pg_ctl.stop"
            else:raise Rejected()
        elif record.name=="postgres":
            if args!=owner._postgres_args():raise Rejected()
            operation="postgres.foreground"
        elif args!=("-D",str(owner.work/"data"),"-U","e2_owner","--auth=trust","--no-locale","-E","UTF8"):raise Rejected()
        output.append({"ordinal":ordinal,"operation":operation,"processRole":role,"retainedPid":record.handle.pid,
                       "exitCode":record.exit_code,"reaped":True,"groupQuiet":True,
                       "ownershipObservation":"retained-group-quiet-at-owner-reap-only"})
    return output


def run_owner(owner, *, disposal, policy=None, source_root=PROJECT):
    """Only sanitized facts escape; finish_owner precedes disposal and receipt."""
    lease=None;body=False;cleanup={"completed":False};private=None
    try:
        owner.verify_source_admission(source_root);owner.install();owner.initialize()
        lease=disposal.acquire(owner)
        if policy is not None:policy.admit_fixture_files(owner.work/"data")
        owner.start_postgres();owner.wait_startup();owner.run_public_schedule()
        owner.verify_private_policy();private=owner.launch_private_sql();body=True
    except BaseException:owner.unqualified=True
    finally:cleanup=owner.finish_owner()
    facts={"scope":SCOPE,"status":"PRIVATE_APPOINTMENT_INCOMPLETE","fullS5Qualified":False,
           "S6":"NOT_RUN","S7":"NOT_RUN","externalOwnerExit":"PENDING_ROOT_RECEIPT",
           "privateDataDisposal":"private-data-disposal-rejected","privateDataDisposed":False,
           "privacyQualificationGap":True,"positiveCallsExecuted":0,"retainedMetadataStatus":"unavailable"}
    if isinstance(owner.backend,owner._positive_adapter.base.Native) and owner._positive_started:
        # Unknown/cleared private diagnostics cannot establish how many of the
        # real checks ran before failure. Never turn that uncertainty into 0.
        facts["positiveCallsExecuted"]=None
    if type(lease) is disposal.DataLease:
        facts["ownedWork"]={"path":str(lease.work),"runId":lease.run_id,
            "markerPath":str(lease.work/"guardian-owned.json"),"markerIdentity":list(lease.root_marker_identity),
            "markerSha256":hashlib.sha256(lease.root_marker_bytes).hexdigest(),"workIdentity":list(lease.work_identity),
            "dataPath":str(lease.work/"data"),"disposedDataIdentity":list(lease.data_identity),
            "dataMarkerSha256":hashlib.sha256(lease.marker_bytes).hexdigest(),
            "socketPath":str(lease.work/"socket"),"socketIdentity":list(lease.socket_identity),
            "postmasterPidPath":str(lease.work/"data/postmaster.pid"),"identityObservation":"captured-before-credentials"}
    # A receipt/reconciliation fault must not skip the separate privacy gate.
    # finish_owner has returned; no Guardian cleanup method is called again.
    owner._disposal_boundary=True
    try:
        if lease is not None:
            disposed=disposal.dispose(owner,lease,cleanup)
            if (type(disposed) is disposal.DisposalResult and type(disposed.disposed) is bool
                    and disposed.code in ("private-data-disposed","private-data-disposal-rejected")):
                facts.update(privateDataDisposal=disposed.code,privateDataDisposed=disposed.disposed,
                             privacyQualificationGap=disposed.disposed is not True)
    except BaseException:pass
    if "ownedWork" in facts:
        facts["ownedWork"].update(identityRecheckedByDisposal=facts["privateDataDisposed"] is True,
            dataRootAbsentAfterDisposal=facts["privateDataDisposed"] is True,
            postmasterPidAbsentBeforeDisposal=cleanup.get("postmasterPidAbsent") is True,
            socketEmptyAfterCleanup=cleanup.get("socketDirectoryEmpty") is True)
    try:
        operations=retained_metadata(owner)
        empty=all_logs_empty_or_retired(owner)
        if lease is None:raise Rejected()
        ended=owner.clock()
        finite=(type(ended) in (int,float) and math.isfinite(ended) and owner.started<=ended<owner.started+900)
        adapter=owner._positive_adapter
        native=(type(owner.backend) is adapter.PrivateNative and owner.backend.guardian is owner
                and owner.backend._factory is adapter.subprocess.Popen
                and owner.backend.spawn.__func__ is adapter.SinkRouting.spawn and owner._consumer is not None
                and owner._consumer.provenance is True and owner._consumer.max_read<=256)
        complete=(native and body and private is not None and private.outcome=="stream-finished"
                  and private.diagnostic.stage=="complete" and private.diagnostic.count==13
                  and type(private.diagnostic.exit) is int and private.diagnostic.exit==0
                  and private.stdout_eof is True and private.stderr_eof is True and private.child_reaped is True)
        server_devnull=(native and owner.postgres is not None and owner.postgres.handle.stdout is None
                        and owner.postgres.handle.stderr is None)
        facts.update(bodyComplete=body,privateStream=(private.evidence() if private is not None else None),
            cleanupProven=cleanup.get("completed") is True,allRetainedReapedGroupQuiet=True,
            ownerQualificationEligible=cleanup.get("qualificationEligible") is True,
            fixedGucGateCompletedBeforePrivateLaunch=owner._guc_retired is True,
            effectivePrivateGucsBeforeCredentials=(native and owner._guc_retired is True),
            serverDevnullFromPinnedFactory=server_devnull,
            allPublicOriginalLogsRetired=owner.public_logs_retired(),emptyOrRetiredLogs=empty,
            sameDatabaseWhole27CatalogMetadataAndSixCountsRawBytesComparedInServer=complete,
            retainedRawSnapshots=False,rollbackAndConnectionClosure=complete,
            nativeProvenance=native,originalDeadlinesPreserved=(owner.qualification_deadline==owner.started+900 and owner.emergency_deadline==owner.started+960),
            positiveCallsExecuted=(11 if complete else facts["positiveCallsExecuted"]),
            positiveCallChecksProvenComplete=(11 if complete else 0),
            withinOriginal900=finite,operations=operations,publicOperations=owner._public_receipts,
            retainedMetadataStatus="validated-after-finish-owner",
            timing={"originalStarted":owner.started,"workDeadline":owner.started+840,"qualificationDeadline":owner.started+900,
                    "cleanupDeadline":owner.started+960,"ended":ended if finite else None,
                    "elapsedSeconds":ended-owner.started if finite else None})
        if all(facts.get(key) is True for key in ("bodyComplete","cleanupProven","ownerQualificationEligible","effectivePrivateGucsBeforeCredentials",
                "serverDevnullFromPinnedFactory","allPublicOriginalLogsRetired","emptyOrRetiredLogs","privateDataDisposed","sameDatabaseWhole27CatalogMetadataAndSixCountsRawBytesComparedInServer",
                "rollbackAndConnectionClosure","nativeProvenance","originalDeadlinesPreserved","withinOriginal900")):
            facts["status"]="PROVISIONAL_ELEVEN_SUBSET_PENDING_ROOT_REVIEW"
    except BaseException:pass
    return facts


def valid_admission(value,freeze_sha):
    return (type(value) is dict and set(value)=={"scope","freezeSha256","rootReviewed"}
            and type(value["scope"]) is str and value["scope"]==SCOPE
            and type(value["freezeSha256"]) is str and value["freezeSha256"]==freeze_sha and value["rootReviewed"] is True)


def _strict_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise Rejected()
        result[key]=value
    return result


def _safe_admission_directory(path):
    path=Path(path)
    if not path.is_absolute() or any(parent.is_symlink() for parent in (path,*path.parents)):raise Rejected()
    info=None
    for parent in reversed((path,*path.parents)):
        if parent==Path("/"):continue
        try:current=parent.lstat()
        except OSError:raise Rejected() from None
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid!=TRUSTED_ADMISSION_UID
                or stat.S_IMODE(current.st_mode)&0o022):raise Rejected()
        if parent==path:info=current
    if info is None:raise Rejected()
    return info


def _read_sealed_file(path,owner_uid=TRUSTED_ADMISSION_UID):
    path=Path(path)
    if (not path.is_absolute() or str(path)!=os.path.normpath(str(path))
            or any(parent.is_symlink() for parent in (path,*path.parents))):raise Rejected()
    before=path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner_uid or before.st_nlink!=1
            or stat.S_IMODE(before.st_mode)!=0o444):raise Rejected()
    try:fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0))
    except OSError:raise Rejected() from None
    with os.fdopen(fd,"rb") as stream:
        opened=os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_dev!=before.st_dev or opened.st_ino!=before.st_ino
                or opened.st_uid!=owner_uid or opened.st_nlink!=1 or stat.S_IMODE(opened.st_mode)!=0o444):raise Rejected()
        raw=stream.read(4*MIB+1)
    if len(raw)>4*MIB:raise Rejected()
    return raw


def _read_pinned_evidence(path):
    path=Path(path)
    if not path.is_absolute() or any(parent.is_symlink() for parent in (path,*path.parents)):raise Rejected()
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>4*MIB:raise Rejected()
    try:fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0))
    except OSError:raise Rejected() from None
    with os.fdopen(fd,"rb") as stream:
        opened=os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_dev!=before.st_dev or opened.st_ino!=before.st_ino
                or opened.st_nlink!=1 or opened.st_size>4*MIB):raise Rejected()
        raw=stream.read(4*MIB+1)
    if len(raw)>4*MIB:raise Rejected()
    return hashlib.sha256(raw).hexdigest()


def reviewed_admission(path,freeze_sha,expected_counts):
    """Validate an admission stored under the independently protected OS root."""
    admission_root=ADMISSION_ROOT
    candidate=Path(path)
    if (not candidate.is_absolute() or str(candidate)!=os.path.normpath(str(candidate))
            or candidate.name!="native-admission.json" or candidate.parent.parent!=admission_root
            or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",candidate.parent.name) is None):raise Rejected()
    _safe_admission_directory(admission_root)
    directory_info=_safe_admission_directory(candidate.parent)
    if directory_info.st_dev!=admission_root.lstat().st_dev:raise Rejected()
    admission_raw=_read_sealed_file(candidate)
    receipt_raw=_read_sealed_file(candidate.parent/"receipt.json")
    try:
        admission=json.loads(admission_raw,object_pairs_hook=_strict_object)
        receipt=json.loads(receipt_raw,object_pairs_hook=_strict_object)
    except BaseException:raise Rejected() from None
    if not valid_admission(admission,freeze_sha):raise Rejected()
    if (type(receipt) is not dict
            or receipt.get("status")!="ROOT_ELEVEN_SOURCE_TOOL_PROOF_ADMITTED_NOT_STARTED"
            or receipt.get("sourceFreezeSha256")!=freeze_sha
            or receipt.get("sourceReviewClosed") is not True
            or receipt.get("sourceAdmissionNoNativeCalls") is not True
            or receipt.get("fullS5Qualified") is not False
            or receipt.get("nativeAdmissionSha256")!=hashlib.sha256(admission_raw).hexdigest()
            or receipt.get("sourceAndToolCounts")!=expected_counts):raise Rejected()
    pins=((SIX_RECEIPT_PATH,SIX_RECEIPT_SHA),(CTAS_RECEIPT_PATH,CTAS_RECEIPT_SHA))
    for relative,expected in pins:
        if _read_pinned_evidence(PROJECT/relative)!=expected:raise Rejected()
    if (receipt.get("acceptedSixReceiptSha256")!=SIX_RECEIPT_SHA
            or receipt.get("previousCtasCleanupReceiptSha256")!=CTAS_RECEIPT_SHA):raise Rejected()
    return admission


def native(admission):
    # Establish trusted ownership before consuming any runtime manifests.
    protected_path(HERE);protected_path(PROJECT)
    protected_path(HERE/"controller.py");protected_path(HERE/"freeze.json");protected_path(HERE/"tools.json")
    protected_path(HERE/"source-inputs.json")
    protected_runtime_modules()
    started=time.monotonic();freeze=read_json(HERE/"freeze.json");freeze_sha=digest(HERE/"freeze.json")
    tools=read_json(HERE/"tools.json")
    expected_counts=dict(sourcePins=len(freeze["sourceSha256"]),originalAuthorityPins=len(read_json(HERE/"source-inputs.json")["sha256"]),acceptedToolPins=49,localStdlibPins=2)
    reviewed_admission(admission,freeze_sha,expected_counts)
    if sys.executable!=tools["pythonPath"] or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode:raise Rejected()
    private_environment();before=verify_inputs(freeze,tools,require_root=True)
    adapter=load("_positive_private_adapter",HERE/"closed_dependencies/private_guardian_staging/private_guardian.py",ADAPTER_SHA)
    disposal=load("_positive_disposal",HERE/"disposal.py",freeze["sourceSha256"]["disposal.py"])
    policy=load("_positive_resource_policy",HERE/"closed_dependencies/resource_policy.py",POLICY_SHA).ResourcePolicy()
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
    if resource.getrlimit(resource.RLIMIT_CORE)!=(0,0):raise Rejected()
    fs=os.statvfs("/private/tmp")
    if fs.f_bavail*fs.f_frsize<WORK_LIMIT:raise Rejected()
    work=Path(tempfile.mkdtemp(prefix="lpa-",dir="/private/tmp")).resolve();os.chmod(work,0o700)
    if re.fullmatch("lpa-[a-z0-9_]{8}",work.name) is None or len(os.fsencode(work/"socket/.s.PGSQL.55439"))>=104:raise Rejected()
    clock=AppointmentClock(started,work)
    executables={name:adapter.base.Executable(PROJECT/tools["postgresRoot"]/"Contents/Versions/18/bin"/name,
                    tools["postgresFiles"]["Contents/Versions/18/bin/"+name]) for name in ("initdb","postgres","pg_ctl","psql")}
    cls=guardian_type(adapter);owner=cls.__new__(cls);owner._construction_complete=False;owner._disposal_boundary=False
    constructed=False
    try:
        owner.__init__(work,executables,started=started,clock=clock,log_policy=policy)
        clock.guardian=owner
    except BaseException:
        owner.finish_owner()
    else:constructed=True
    if not constructed:raise Rejected()
    result=run_owner(owner,disposal=disposal,policy=policy)
    result["sourceToolPinsBeforeAfterEqual"]=False
    result["resourceWithinBounds"]=False
    try:
        after=verify_inputs(freeze,tools,require_root=True)
        result["sourceToolPinsBeforeAfterEqual"]=before==after and digest(HERE/"freeze.json")==freeze_sha
    except BaseException:pass
    try:
        result["resourceWithinBounds"]=(not clock.resource_failed and allocated(work)<=WORK_LIMIT
            and resource.getrlimit(resource.RLIMIT_FSIZE)==(32*MIB,32*MIB)
            and resource.getrlimit(resource.RLIMIT_CORE)==(0,0))
        result["resourcePolicy"]=policy.metadata()
    except BaseException:pass
    final_ended=time.monotonic()
    result["finalWithinOriginal900"]=math.isfinite(final_ended) and started<=final_ended<started+900
    if "timing" in result:
        result["timing"].update(finalEvidenceEnded=final_ended,finalMeasuredElapsedSeconds=final_ended-started)
    result["compactEvidenceWithin256MiB"]=len(json.dumps(result,sort_keys=True).encode("ascii"))<=256*MIB
    if (result["sourceToolPinsBeforeAfterEqual"] is not True or result["resourceWithinBounds"] is not True
            or result["finalWithinOriginal900"] is not True or result["compactEvidenceWithin256MiB"] is not True):
        result["status"]="PRIVATE_APPOINTMENT_INCOMPLETE"
    return result


def main(argv):
    if not argv:return {"scope":SCOPE,"status":"PREPARED_NOT_EXECUTED","native":"NOT_RUN","positiveCallsExecuted":0,
                        "fullS5Qualified":False,"nativeAdmission":"NOT_GRANTED"},0
    if len(argv)!=2 or argv[0]!="--native-admission":return {"scope":SCOPE,"status":"REJECTED","fullS5Qualified":False},1
    try:
        result=native(argv[1]);return result,0 if result["status"]=="PROVISIONAL_ELEVEN_SUBSET_PENDING_ROOT_REVIEW" else 1
    except BaseException:return {"scope":SCOPE,"status":"FAILED","fullS5Qualified":False,"externalOwnerExit":"PENDING_ROOT_RECEIPT"},1


if __name__=="__main__":
    result,code=main(sys.argv[1:]);print(json.dumps(result,sort_keys=True));raise SystemExit(code)
