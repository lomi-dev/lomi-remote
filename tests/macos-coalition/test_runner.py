"""Evidence rejection checks; these tests never register launchd jobs."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import os
import subprocess
import sys
import tempfile

SPEC = importlib.util.spec_from_file_location("coalition_runner", Path(__file__).with_name("run_native.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
sys.path.insert(0, str(Path(__file__).parent))
import admission
import reparent


def observation():
    samples = {}
    for phase, pid, sid in (("self", 100, 1), ("fork", 101, 1), ("setsid", 101, 101), ("exec", 101, 101)):
        samples[phase] = {"outcome": "Observed", "bytes": 40, "pid": pid, "sid": sid, "resource": 20, "jetsam": 21}
    usage = {phase: {"outcome": "Observed", "started": active + 5, "exited": 5, "active": active}
             for phase, active in zip(("before", "fork", "setsid", "exec", "afterWait"), (1, 2, 2, 2, 1))}
    usage.update(invalidId={"outcome": "Unknown", "active": None}, missingSymbol={"outcome": "Unsupported", "active": None})
    return dict(schema=1, privateAbiBytes=40, numericSignalsUsed=False, reparent="Unrun", cleanupConfirmed=True,
                retainedChild=True, outcome="Observed", resourceUsage=usage, **samples)


class EvidenceTests(unittest.TestCase):
    def test_valid_owned_child(self):
        self.assertTrue(RUNNER.validate_observation(observation()))

    def test_cleanup_failure_cannot_pass(self):
        for value in (False, "true", 1, None):
            candidate = observation()
            candidate["cleanupConfirmed"] = value
            with self.assertRaises(RuntimeError):
                RUNNER.validate_observation(candidate)

    def test_error_is_never_zero(self):
        for phase in ("invalidId", "missingSymbol"):
            candidate = observation()
            candidate["resourceUsage"][phase]["active"] = 0
            with self.assertRaises(RuntimeError):
                RUNNER.validate_observation(candidate)

    def test_missing_or_inconsistent_counts_cannot_pass(self):
        for change in ({"outcome": "Unknown"}, {"active": 0}, {"started": True}, {"exited": -1}):
            candidate = observation()
            candidate["resourceUsage"]["afterWait"].update(change)
            self.assertFalse(RUNNER.validate_observation(candidate))

    def test_replaced_identity_or_lost_inheritance_cannot_pass(self):
        for phase, field, value in (("exec", "pid", 102), ("setsid", "resource", 22), ("fork", "sid", 9), ("self", "jetsam", 0)):
            candidate = copy.deepcopy(observation())
            candidate[phase][field] = value
            self.assertFalse(RUNNER.validate_observation(candidate))


class ReparentTests(unittest.TestCase):
    def value(self, failure=False):
        owner = {"outcome": "Observed", "bytes": 40, "pid": 100, "sid": 1, "resource": 20, "jetsam": 21}
        leaf = dict(owner, pid=102)
        orphan = dict(leaf, sid=102)
        usages = {key: {"outcome": "Observed", "started": 5 + count, "exited": 5, "active": count} for key, count in (("initial", 1), ("together", 3), ("orphan", 2), ("final", 1))}
        return dict(schema="reparent-v1", cleanupConfirmed=True, numericSignalsUsed=False, execBeforeRegistration=True,
                    middleOwnedWait=True, leafWaitByMiddle=failure, leafExitEvent=not failure, orphaned=not failure,
                    registrationAccepted=not failure, auditValidAfterExec=True, leafObservedPpid=1,
                    scenario="registration-failure" if failure else "normal", outcome="Unrun" if failure else "Observed",
                    self=owner, middle=dict(owner, pid=101), leafBefore=leaf, leafSetsid=orphan, leafExec=orphan,
                    leafReparented=orphan, usage=usages)

    def test_normal_and_retained_failure_control(self):
        self.assertTrue(reparent.validate(self.value()))
        self.assertTrue(reparent.validate(self.value(True), failure_case=True))

    def test_missing_true_exit_or_counter_never_passes(self):
        for field in ("leafExitEvent", "middleOwnedWait", "auditValidAfterExec"):
            value = self.value()
            value[field] = False
            self.assertFalse(reparent.validate(value))
        value = self.value()
        value["usage"]["final"]["active"] = 0
        self.assertFalse(reparent.validate(value))

    def test_registration_failure_never_orphans(self):
        value = self.value(True)
        value["orphaned"] = True
        self.assertFalse(reparent.validate(value, failure_case=True))

    def test_reparented_foreign_coalition_rejected(self):
        value = self.value()
        value["leafReparented"] = dict(value["leafReparented"], resource=22)
        self.assertFalse(reparent.validate(value))


class AdmissionTests(unittest.TestCase):
    def matrix(self):
        result = {"jobs": {}}
        for suffix, base in (("a", 100), ("b", 200)):
            original = {"nonce": suffix + "1", "self": {"pid": base, "resource": base + 1, "jetsam": base + 2}}
            repeated = {"nonce": suffix + "2", "self": dict(original["self"], pid=base + 10)}
            fresh = {"nonce": suffix + "3", "self": {"pid": base + 20, "resource": base + 21, "jetsam": base + 22}}
            post = [original] if suffix == "a" else [original, repeated]
            sample = {"self": original["self"], "usage": {"outcome": "Observed", "started": 2, "exited": 1, "active": 1}}
            result["jobs"][suffix] = {"phases": {"initial": [original], "live": [original], "repeat": [original], "postExit": post, "rebootstrap": post + [fresh]}, "samples": {phase: copy.deepcopy(sample) for phase in ("live", "repeat", "final")}}
        return result

    def test_finite_admission_matrix(self):
        self.assertTrue(admission.validate_matrix(self.matrix(), (1, 2)))

    def test_false_control_missing_second_entry_is_unknown(self):
        result = self.matrix()
        result["jobs"]["b"]["phases"]["postExit"].pop()
        self.assertFalse(admission.validate_matrix(result, (1, 2)))

    def test_hidden_counter_change_or_query_error_is_unknown(self):
        for change in ({"started": 3, "exited": 2}, {"outcome": "Unknown"}, {"active": 0}):
            result = self.matrix()
            result["jobs"]["a"]["samples"]["repeat"]["usage"].update(change)
            self.assertFalse(admission.validate_matrix(result, (1, 2)))

    def test_no_coalition_generation_change_is_unknown(self):
        result = self.matrix()
        record = result["jobs"]["a"]["phases"]["rebootstrap"][-1]
        record["self"]["resource"] = result["jobs"]["a"]["phases"]["initial"][0]["self"]["resource"]
        self.assertFalse(admission.validate_matrix(result, (1, 2)))


class DurabilityTests(unittest.TestCase):
    def test_post_replace_sync_failure_requires_retry_barrier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_sync = RUNNER.os.fsync
            directory_syncs = []
            fail = [True]
            def sync(fd):
                if RUNNER.stat.S_ISDIR(os.fstat(fd).st_mode):
                    directory_syncs.append(fd)
                    if fail[0]:
                        fail[0] = False
                        raise OSError("injected directory sync failure after replace")
                real_sync(fd)
            checkpoint = {"controllerExit": {"lockInode": 123, "resultSha256": "a" * 64}}
            with patch.object(RUNNER.os, "fsync", side_effect=sync):
                with self.assertRaises(OSError):
                    RUNNER.durable_receipt(root, "recovery.json", checkpoint)
                self.assertEqual(RUNNER.json.loads((root / "recovery.json").read_text()), checkpoint)
                RUNNER.durable_receipt(root, "recovery.json", checkpoint)
            self.assertEqual(len(directory_syncs), 2)


class RecoveryIdentityTests(unittest.TestCase):
    def test_paths_are_derived_from_uuid_not_journal(self):
        root = RUNNER.BASE / "11111111-1111-4111-8111-111111111111"
        binary = root / "probe"
        job, content = RUNNER.fixed_job(root, binary, "gui-aqua", "a")
        job["plistSha256"] = RUNNER.hashlib.sha256(content).hexdigest()
        self.assertEqual(RUNNER.validate_recovery_jobs({"jobs": [job]}, root, binary), {job["label"]: content})
        for field in ("target", "plist", "profile", "state", "domain"):
            changed = copy.deepcopy(job)
            changed[field] += "foreign"
            with self.assertRaises(RuntimeError):
                RUNNER.validate_recovery_jobs({"jobs": [changed]}, root, binary)
        with self.assertRaises(RuntimeError):
            RUNNER.validate_recovery_jobs({"jobs": [job, job]}, root, binary)


class CleanupTests(unittest.TestCase):
    def test_one_uncertain_job_does_not_skip_other_owned_jobs(self):
        visited = []
        def cleanup(job):
            visited.append(job["label"])
            if job["label"] == "uncertain":
                raise RuntimeError("still busy")
            job["cleanupConfirmed"] = True
        jobs = [{"label": "other"}, {"label": "uncertain"}]
        failures = RUNNER.cleanup_all(jobs, cleanup)
        self.assertEqual(visited, ["uncertain", "other"])
        self.assertEqual(len(failures), 1)
        self.assertTrue(jobs[0]["cleanupConfirmed"])

    def test_completed_result_is_not_controller_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary)
            (profile / "result.json").write_text('{"cleanupConfirmed":true}')
            script = "import fcntl,os,sys; f=open(sys.argv[1],'x'); os.chmod(sys.argv[1],0o600); fcntl.flock(f,fcntl.LOCK_EX); print('ready',flush=True); sys.stdin.read(1)"
            child = subprocess.Popen([sys.executable, "-B", "-c", script, str(profile / "controller.lock")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                with patch.object(RUNNER, "directory", side_effect=lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY)):
                    with self.assertRaisesRegex(RuntimeError, "controller_exit_unconfirmed"):
                        RUNNER.wait_controller_exit(profile, timeout=0.01)
                    child.stdin.close()
                    self.assertEqual(child.wait(timeout=2), 0)
                    descriptor = RUNNER.wait_controller_exit(profile, timeout=0.1)
                    os.close(descriptor)
            finally:
                if not child.stdin.closed:
                    child.stdin.close()
                child.wait(timeout=2)
                child.stdout.close()

    def test_missing_or_malformed_lock_is_uncertain(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary)
            with patch.object(RUNNER, "directory", side_effect=lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY)):
                with self.assertRaises(FileNotFoundError):
                    RUNNER.wait_controller_exit(profile, timeout=0)
                (profile / "controller.lock").write_text("not a lifetime lock")
                (profile / "controller.lock").chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, "controller_lifetime_unconfirmed"):
                    RUNNER.wait_controller_exit(profile, timeout=0)


if __name__ == "__main__":
    unittest.main()
