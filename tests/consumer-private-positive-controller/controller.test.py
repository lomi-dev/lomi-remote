"""Pure retained fake integration. No Native processes/pipes/selectors/signals."""
import ctypes  # CPython bootstrap before explicit native-operation audit rejection.
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

AUDIT={"children":0,"network":0,"native_pipe":0}


def audit(event,args):
    if event in ("subprocess.Popen","os.system","os.fork","os.forkpty","os.posix_spawn","os.exec","os.spawn","os.kill","os.killpg","ctypes.dlopen"):
        AUDIT["children"]+=1;raise RuntimeError("native operation forbidden")
    if event.startswith("socket."):
        AUDIT["network"]+=1;raise RuntimeError("network forbidden")


sys.addaudithook(audit)
HERE=Path(__file__).resolve().parent


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


c=load("private_positive_controller_test_target",HERE/"controller.py")
f=load("private_positive_closed_fakes",HERE/"closed_dependencies/private_guardian_staging/private_guardian.test.py")
a=f.m
d=load("private_positive_disposal_test_target",HERE/"disposal.py")
authority=c.load("private_positive_authority_test_target",HERE/"closed_dependencies/authority.py",c.AUTHORITY_SHA)
snapshot=load("private_positive_snapshot_test_target",HERE/"snapshots.py")
CANARY="SYNTHETIC_PRIVATE_CONTROLLER_CANARY_90BC"
GOOD=b"".join(a.streams._diagnostics.notice_line(i) for i in range(13))


class Backend(f.Fake):
    def __init__(self,clock,references):
        super().__init__(clock);self.references=references
    def factory(self,argv,**options):
        if Path(argv[0]).name=="initdb":(self.guardian.work/"data").mkdir(mode=0o700)
        if self.guardian._spawn_route[0]=="public":
            entry=self.guardian._active_public
            if entry is not None and entry["kind"] in ("catalog","metadata"):
                rows=self.references[entry["referenceState"]][entry["kind"]]
                self.public_stdout=("\n".join(json.dumps(row) for row in rows)+"\n").encode()
            else:self.public_stdout=None
        return super().factory(argv,**options)


class ControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.originals={name:getattr(c.os,name) for name in ("read","pipe","set_blocking","kill","killpg")}
        def deny(*args):
            AUDIT["native_pipe"]+=1;raise RuntimeError("native operation forbidden")
        for name in cls.originals:setattr(c.os,name,deny)
    @classmethod
    def tearDownClass(cls):
        for name,value in cls.originals.items():setattr(c.os,name,value)
        if any(AUDIT.values()) or any(f.AUDIT.values()):raise AssertionError("pure audit rejected")
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="private-positive-fake-")
        self.root=Path(self.temp.name).resolve();self.work=self.root/"work";self.work.mkdir(mode=0o700)
        self.clock=f.Clock()
        self.references={state:{kind:json.loads((HERE/f"reference-{state}-{kind}.json").read_bytes())
                               for kind in ("catalog","metadata")} for state in ("old","new")}
        self.backend=Backend(self.clock,json.loads(json.dumps(self.references)))
        tools={}
        for name in ("initdb","postgres","pg_ctl","psql"):
            path=self.root/name;path.write_text("inert "+name)
            tools[name]=a.base.Executable(path,hashlib.sha256(path.read_bytes()).hexdigest())
        self.cls=c.guardian_type(a)
        self.owner=self.cls(self.work,tools,started=0.0,backend=self.backend,clock=self.clock,sleep=self.clock.sleep,
            signals=f.Signals(),io_factory=lambda record:f.FakeIO(record,self.clock),
            registry=c.read_json(HERE/"public-registry.json"),source_pins={"private-positive-driver.sql":c.digest(HERE/"private-positive-driver.sql")},
            authority=authority,references=self.references)
    def tearDown(self):
        if not self.owner._emergency_sink.closed:self.owner.finish_owner()
        self.temp.cleanup()
    def run_owner(self):
        facts=c.run_owner(self.owner,disposal=d)
        self.assertTrue(self.owner._emergency_sink.closed)
        self.assertNotIn(CANARY,json.dumps(facts));self.assertNotIn(CANARY,repr(facts))
        self.assertFalse(facts["fullS5Qualified"])
        self.assertEqual(facts["positiveCallsExecuted"],0)  # Fakes prove no actual SQL.
        return facts

    def test_protected_path_requires_owned_nonwritable_closure(self):
        root=self.root/"protected";root.mkdir(mode=0o700)
        directory=root/"closed";directory.mkdir(mode=0o700)
        source=directory/"source.py";source.write_text("VALUE = 7\n")
        source.chmod(0o400);directory.chmod(0o500);root.chmod(0o500)
        try:
            self.assertEqual(c.protected_path(source,uid=os.getuid(),boundary=root),source)
            source.chmod(0o600)
            with self.assertRaises(c.Rejected):
                c.protected_path(source,uid=os.getuid(),boundary=root)
        finally:
            root.chmod(0o700);directory.chmod(0o700)

    def test_loader_executes_the_verified_bytes_after_path_replacement(self):
        path=self.root/"candidate.py";verified=b"VALUE = 'verified'\n"
        expected=hashlib.sha256(verified).hexdigest()
        path.write_bytes(verified)
        admitted=path.read_bytes()
        self.assertEqual(hashlib.sha256(admitted).hexdigest(),expected)
        path.write_text("VALUE = 'replacement'\n")
        module=c.load_verified_source("verified_bytes_fixture",path,admitted,expected)
        self.assertEqual(module.VALUE,"verified")

    def test_default_and_admission_remain_closed_childless(self):
        self.assertEqual(c.main([])[0]["native"],"NOT_RUN")
        good={"scope":c.SCOPE,"freezeSha256":"a"*64,"rootReviewed":True}
        self.assertTrue(c.valid_admission(good,"a"*64))
        for value in (1,"true",None,False):self.assertFalse(c.valid_admission({**good,"rootReviewed":value},"a"*64))
        self.assertEqual(self.backend.calls,[])

    def test_root_admission_rejects_caller_owned_forged_receipt(self):
        root=self.root/"admissions";root.mkdir(mode=0o700)
        directory=root/"12345678-1234-4234-8234-123456789abc";directory.mkdir(mode=0o700)
        freeze="f"*64;counts={"sourcePins":88,"originalAuthorityPins":228,"acceptedToolPins":49,"localStdlibPins":2}
        admission={"scope":c.SCOPE,"freezeSha256":freeze,"rootReviewed":True}
        admission_path=directory/"native-admission.json"
        admission_raw=(json.dumps(admission,sort_keys=True)+"\n").encode();admission_path.write_bytes(admission_raw);admission_path.chmod(0o444)
        receipt={"status":"ROOT_ELEVEN_SOURCE_TOOL_PROOF_ADMITTED_NOT_STARTED",
            "sourceFreezeSha256":freeze,"sourceReviewClosed":True,"sourceAdmissionNoNativeCalls":True,
            "fullS5Qualified":False,"nativeAdmissionSha256":hashlib.sha256(admission_raw).hexdigest(),
            "sourceAndToolCounts":counts,"acceptedSixReceiptSha256":c.SIX_RECEIPT_SHA,
            "previousCtasCleanupReceiptSha256":c.CTAS_RECEIPT_SHA}
        receipt_path=directory/"receipt.json";receipt_path.write_text(json.dumps(receipt)+"\n");receipt_path.chmod(0o444)
        with self.assertRaises(c.Rejected):c.reviewed_admission(admission_path,freeze,counts)
        with self.assertRaises(c.Rejected):c._safe_admission_directory(directory)

    def test_native_constructor_rejects_caller_registry_before_native_initialization(self):
        owner=self.cls.__new__(self.cls);owner._construction_complete=False
        try:
            with self.assertRaises(c.Rejected):
                owner.__init__(self.work,self.owner.tools,started=0.0,registry={"payload":CANARY})
        finally:
            owner.finish_owner()
        self.assertEqual(self.backend.calls,[])

    def test_original_work_clock_preserves_cleanup_reserve(self):
        original_time,original_scan=c.time.monotonic,c.allocated
        calls=[]
        class Owner:
            cleanup_started=True;unqualified=False
            class Cancel:
                def handle(self,sig):calls.append(sig)
            cancel=Cancel()
        try:
            c.time.monotonic=lambda:845.0;c.allocated=lambda work:0
            clock=c.AppointmentClock(0.0,self.work);clock.guardian=Owner()
            self.assertEqual(clock(),845.0)
            self.assertEqual(calls,[])
            clock.guardian.cleanup_started=False
            self.assertEqual(clock(),845.0)
            self.assertEqual(len(calls),1)
            self.assertTrue(clock.guardian.unqualified)
            self.assertEqual(clock.started,0.0)
        finally:c.time.monotonic,c.allocated=original_time,original_scan

    def test_full_fake_phase_order_retirement_pipe_cleanup_and_disposal(self):
        facts=self.run_owner()
        self.assertTrue(facts["bodyComplete"])
        self.assertTrue(facts["allPublicOriginalLogsRetired"])
        self.assertTrue(facts["fixedGucGateCompletedBeforePrivateLaunch"])
        self.assertFalse(facts["effectivePrivateGucsBeforeCredentials"])
        self.assertTrue(facts["privateDataDisposed"])
        self.assertFalse(facts["privacyQualificationGap"])
        self.assertFalse(facts["nativeProvenance"])
        self.assertFalse(facts["sameDatabaseWhole27CatalogMetadataAndSixCountsRawBytesComparedInServer"])
        self.assertEqual(facts["privateStream"]["diagnostic"]["stage"],"complete")
        self.assertEqual(len(facts["publicOperations"]),134)
        self.assertEqual(sum(r["independentReferencePairCompared"] for r in facts["publicOperations"]),4)
        self.assertTrue(all(r["originalLogInodesAndDigestsVerifiedRetired"] for r in facts["publicOperations"]))
        self.assertFalse((self.work/"data").exists())
        self.assertEqual(sum(route=="private" for route,*_ in self.backend.calls),1)
        private=[argv for route,argv,*_ in self.backend.calls if route=="private"][0]
        self.assertEqual(private[-2:],("--file","private-positive-driver.sql"))
        self.assertEqual(tuple(private[1:1+len(a.streams._diagnostics.CLIENT_FLAGS)]),a.streams._diagnostics.CLIENT_FLAGS)
        with self.assertRaises(c.Rejected):self.owner.finish_owner()

    def test_malformed_private_canary_is_sanitized_and_data_still_disposed(self):
        self.backend.private_output=CANARY.encode()+b"\n"
        facts=self.run_owner()
        self.assertTrue(facts["privateDataDisposed"])
        self.assertEqual(facts["privateStream"]["diagnostic"]["stage"],"generic-failure")
        self.assertEqual(facts["privateStream"]["diagnostic"]["count"],0)

    def test_nonzero_after_all_markers_cannot_complete(self):
        self.backend.private_code=3
        facts=self.run_owner()
        self.assertEqual(facts["privateStream"]["diagnostic"]["stage"],"generic-failure")
        self.assertTrue(facts["privateDataDisposed"])

    def test_private_launch_before_guc_or_public_retirement_is_rejected(self):
        with self.assertRaises(c.Rejected):self.owner.launch_private_sql()
        self.assertEqual(self.backend.calls,[])

    def test_wrong_independent_metadata_cannot_self_adopt_target_or_create_credentials(self):
        self.owner._references["old"]["metadata"][0]["owner"]=CANARY
        facts=self.run_owner()
        self.assertFalse(facts["bodyComplete"])
        self.assertFalse(any(route=="private" for route,*_ in self.backend.calls))
        self.assertTrue(facts["privateDataDisposed"])

    def test_retirement_ack_failure_blocks_credential_phase(self):
        original=a.base.Guardian.retire_result
        def fail(*args,**kwargs):raise RuntimeError(CANARY)
        a.base.Guardian.retire_result=fail
        try:facts=self.run_owner()
        finally:a.base.Guardian.retire_result=original
        self.assertFalse(facts["bodyComplete"])
        self.assertFalse(any(route=="private" for route,*_ in self.backend.calls))

    def test_replaced_fixed_wrapper_rejected_before_private_factory(self):
        def spawned(route,handle):
            if route=="public" and Path(self.backend.calls[-1][1][-1]).name=="verify-private-policy.sql":
                (self.work/"private-positive-driver.sql").write_text(CANARY)
        self.backend.on_spawn=spawned
        facts=self.run_owner()
        self.assertFalse(facts["bodyComplete"])
        self.assertFalse(any(route=="private" for route,*_ in self.backend.calls))
        self.assertTrue(facts["privateDataDisposed"])

    def test_no_public_retry_or_arbitrary_sql_after_private_phase(self):
        self.run_owner();calls=len(self.backend.calls)
        for action in (lambda:self.owner.run_public_schedule(),lambda:self.owner.run_public_schema("fixture-ops.sql"),
                       lambda:self.owner._launch("psql",("-c",CANARY))):
            with self.assertRaises(c.Rejected):action()
        self.assertEqual(len(self.backend.calls),calls)

    def test_disposal_failure_keeps_explicit_privacy_gap(self):
        original=d.dispose
        d.dispose=lambda *args:d.DisposalResult("private-data-disposal-rejected",False)
        try:facts=self.run_owner()
        finally:d.dispose=original
        self.assertFalse(facts["privateDataDisposed"])
        self.assertTrue(facts["privacyQualificationGap"])
        self.assertEqual(facts["status"],"PRIVATE_APPOINTMENT_INCOMPLETE")
        self.assertTrue((self.work/"data").is_dir())

    def test_metadata_fault_does_not_skip_owned_data_disposal(self):
        original=c.retained_metadata
        def fail(*args):raise RuntimeError(CANARY)
        c.retained_metadata=fail
        try:facts=self.run_owner()
        finally:c.retained_metadata=original
        self.assertTrue(facts["privateDataDisposed"])
        self.assertEqual(facts["status"],"PRIVATE_APPOINTMENT_INCOMPLETE")
        self.assertFalse((self.work/"data").exists())
        self.assertEqual(facts["ownedWork"]["path"],str(self.work))
        self.assertTrue(facts["ownedWork"]["identityRecheckedByDisposal"])

    def test_silent_wrapper_and_include_remain_exact_pinned_source(self):
        actual=(HERE/"private-positive-driver.sql").read_bytes()
        self.assertEqual(actual,snapshot.private_wrapper((HERE/"sql/public-catalog.sql").read_bytes(),(HERE/"sql/public-metadata.sql").read_bytes()))
        self.assertEqual(actual.count(b"\\ir positive-auth.sql\n"),1)
        self.assertLess(actual.index(b"INSERT INTO pg_temp.lomi_private_baseline"),actual.index(b"\\ir"))
        self.assertGreater(actual.index(b"DO $private_after$"),actual.index(b"\\ir"))
        self.assertEqual(actual.count(b"RAISE NOTICE"),0)
        self.assertEqual(c.digest(HERE/"positive-auth.sql"),a.POSITIVE_SHA256)
        self.assertEqual(c.digest(HERE/"closed_dependencies/private_guardian_staging/private_guardian.py"),c.ADAPTER_SHA)
        with self.assertRaisesRegex(RuntimeError,"^snapshot source rejected$"):
            snapshot.private_wrapper(b"SELECT '"+CANARY.encode()+b"';",(HERE/"sql/public-metadata.sql").read_bytes())


if __name__=="__main__":unittest.main()
