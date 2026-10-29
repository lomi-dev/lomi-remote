"""Synthetic owned filesystem only; no child, pipe, network or signal calls."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest

AUDIT = {"children": 0, "network": 0}


def audit(event, args):
    if event in ("subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.posix_spawn", "os.exec", "os.spawn", "os.kill", "os.killpg", "ctypes.dlopen"):
        AUDIT["children"] += 1
        raise RuntimeError("native operation forbidden")
    if event.startswith("socket."):
        AUDIT["network"] += 1
        raise RuntimeError("network forbidden")


sys.addaudithook(audit)
spec = importlib.util.spec_from_file_location("closed_private_data_disposal", Path(__file__).with_name("disposal.py"))
d = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = d
spec.loader.exec_module(d)
CANARY = "SYNTHETIC_PRIVATE_DATA_CANARY_701A"


class DisposalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="private-disposal-fake-")
        self.work = Path(self.temp.name).resolve()/"owned"
        self.work.mkdir(mode=0o700)
        (self.work/"data").mkdir(mode=0o700)
        (self.work/"socket").mkdir(mode=0o700)
        self.owner = NS(work=self.work, run_id="e8db759e-bdb9-4c9c-a95e-8a9c5a3c4894", started=0.0,
                        clock=lambda: 1.0, qualification_deadline=900.0, emergency_deadline=960.0,
                        _emergency_sink=NS(closed=False), handlers_installed=True)
        self.owner.marker_path = self.work/"guardian-owned.json"
        self.owner.marker_bytes = (json.dumps({"runId":self.owner.run_id,"work":str(self.work),
            "data":str(self.work/"data"),"socket":str(self.work/"socket")},sort_keys=True)+"\n").encode()
        self.owner.marker_path.write_bytes(self.owner.marker_bytes)
        self.owner.marker_path.chmod(0o600)
        self.lease = d.acquire(self.owner)
        pg = NS(name="postgres", forced=False, exit_code=0, reaped=True, group_quiet=True)
        self.owner.postgres = pg
        def ctl(args, code):
            return NS(name="pg_ctl", argv=("known-pgctl", "-D", str(self.work/"data"), *args),
                      exit_code=code, reaped=True, group_quiet=True)
        self.owner.children = [pg, ctl(("status",),0), ctl(("-m","immediate","-w","-t","20","stop"),0), ctl(("status",),3)]
        self.cleanup = {name: True for name in ("completed", "foregroundPostgresRegistered", "startupConfirmed",
            "postmasterNormalExit", "pgCtlStatusAbsent", "postmasterPidAbsent", "socketDirectoryEmpty", "allRetainedChildrenReaped")}
        self.cleanup["ownershipUnresolved"] = False
        self.owner.cleanup_result = self.cleanup
        self.owner._emergency_sink.closed = True
        self.owner.handlers_installed = False

    def tearDown(self):
        self.temp.cleanup()
        self.assertEqual(AUDIT, {"children":0,"network":0})

    def payload(self):
        directory = self.work/"data/base"
        directory.mkdir(mode=0o700)
        path = directory/"1234"
        path.write_text(CANARY)
        path.chmod(0o600)
        return path

    def rejected(self):
        result = d.dispose(self.owner, self.lease, self.cleanup)
        self.assertEqual(result, d.DisposalResult("private-data-disposal-rejected",False))
        self.assertNotIn(CANARY, repr(result))
        self.assertNotIn(CANARY, json.dumps({"code":result.code,"disposed":result.disposed}))
        return result

    def test_dispose_only_original_owned_data_and_retain_public_marker(self):
        self.payload()
        unrelated = self.work.parent/"unrelated"
        unrelated.write_text("unchanged")
        result = d.dispose(self.owner,self.lease,self.cleanup)
        self.assertTrue(result.disposed)
        self.assertEqual(result.code,"private-data-disposed")
        self.assertFalse((self.work/"data").exists())
        self.assertEqual(self.owner.marker_path.read_bytes(),self.owner.marker_bytes)
        self.assertEqual(unrelated.read_text(),"unchanged")
        self.assertTrue((self.work/"socket").is_dir())
        self.assertNotIn(CANARY,repr(self.lease))

    def test_cleanup_failure_never_deletes(self):
        path=self.payload(); self.cleanup["postmasterNormalExit"]=False
        self.rejected(); self.assertTrue(path.exists())

    def test_unreaped_or_group_live_never_deletes(self):
        path=self.payload(); self.owner.children[-1].group_quiet=False
        self.rejected(); self.assertTrue(path.exists())

    def test_bool_stop_exit_cannot_stand_for_zero(self):
        path=self.payload(); self.owner.children[-2].exit_code=False
        self.rejected(); self.assertTrue(path.exists())

    def test_unfinished_owner_rejected(self):
        self.owner._emergency_sink.closed=False
        self.rejected()

    def test_replaced_data_root_rejected_without_blessing_new_inode(self):
        original=self.work/"data-original"; (self.work/"data").rename(original)
        (self.work/"data").mkdir(mode=0o700)
        self.rejected(); self.assertTrue(original.is_dir())

    def test_root_marker_replacement_rejected(self):
        self.owner.marker_path.rename(self.work/"old-marker")
        self.owner.marker_path.write_bytes(self.owner.marker_bytes); self.owner.marker_path.chmod(0o600)
        self.rejected()

    def test_data_marker_changed_rejected(self):
        (self.work/"data"/d.MARKER).write_text(CANARY)
        self.rejected()

    def test_symlink_never_followed_and_external_bytes_retained(self):
        outside=self.work.parent/"outside";outside.write_text(CANARY);outside.chmod(0o600)
        (self.work/"data/linked").symlink_to(outside)
        self.rejected();self.assertEqual(outside.read_text(),CANARY)

    def test_hard_link_rejected_in_preflight_before_any_unlink(self):
        outside=self.work.parent/"outside";outside.write_text(CANARY);outside.chmod(0o600)
        os.link(outside,self.work/"data/linked")
        self.rejected();self.assertTrue((self.work/"data/linked").exists())

    def test_pid_reappearance_rejected(self):
        (self.work/"data/postmaster.pid").write_text("123")
        self.rejected()

    def test_socket_reappearance_rejected(self):
        (self.work/"socket/reappeared").write_text("synthetic")
        self.rejected()

    def test_expired_original_deadline_stops_disposal(self):
        self.owner.clock=lambda: 900.0
        self.rejected()

    def test_entry_bound_rejects_before_any_deletion(self):
        path=self.payload();old=d.MAX_ENTRIES;d.MAX_ENTRIES=1
        try:self.rejected()
        finally:d.MAX_ENTRIES=old
        self.assertTrue(path.exists())

    def test_partial_unlink_failure_unqualified_and_attempt_not_renewed(self):
        self.payload();original=d.os.unlink;calls=[]
        def fail(name,**options):
            calls.append(True)
            if len(calls)>1:raise RuntimeError(CANARY)
            return original(name,**options)
        d.os.unlink=fail
        try:self.rejected()
        finally:d.os.unlink=original
        self.rejected()
        self.assertTrue((self.work/"data").is_dir())


if __name__=="__main__":unittest.main()
