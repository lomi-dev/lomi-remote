import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_ssh_disconnect as executor

OWNER = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
START = dict(phase='start', qualified=False, serviceRunningAtSshExit=True, manualStart=True,
             checkpointWritten=True, ownerEpoch=OWNER, sessionEpoch=OWNER, childPid=100,
             workerPid=101, inputWrites=0)
VERIFY = dict(phase='verify', qualified=False, unchangedOwnerSessionChildWorker=True,
              noInputReplayAcrossSshDisconnect=True, resize37x101=True,
              afterDetachInputObserved=True, onlyTwoExpectedInputWrites=True)
CLEANUP = dict(phase='cleanup', qualified=False, currentOwnerStopProofVerified=True,
               serviceAbsent=True, privateUuidDirectoryAbsent=True,
               checkpointRemoved=True, ownedFixtureProcesses=0)


class ExecutionFailures(unittest.TestCase):
    def run_case(self, bad=None, failure=None):
        calls = []
        gaps = []
        plan = {key: 'synthetic' for key in ('runId', 'snapshot', 'sourceInventoryDigest', 'archiveDigest', 'nativeProof', 'nativeProofSha256')}
        plan['commands'] = [dict(phase=p, command=[p], scriptSha256='synthetic', timeoutSeconds=30)
                            for p in ('start', 'verify', 'cleanup')]

        def run(argv, **kwargs):
            phase = argv[0]
            calls.append(phase)
            if phase == bad:
                if failure == 'timeout':
                    raise subprocess.TimeoutExpired(argv, 30)
                if failure == 'interrupt':
                    raise KeyboardInterrupt()
                if failure == 'transport':
                    return subprocess.CompletedProcess(argv, 255, '', '')
                if failure == 'remote':
                    return subprocess.CompletedProcess(argv, 1, '', '')
                if failure == 'malformed':
                    return subprocess.CompletedProcess(argv, 0, '{bad', '')
            return subprocess.CompletedProcess(argv, 0, json.dumps({'start': START, 'verify': VERIFY, 'cleanup': CLEANUP}[phase]), '')

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'evidence.json'
            code = executor.execute(plan, path, run, lambda seconds: gaps.append((seconds, list(calls))))
            report = json.loads(path.read_text())
        return code, calls, gaps, report

    def test_success_is_strictly_sequential_with_gap_after_first_exit(self):
        code, calls, gaps, report = self.run_case()
        self.assertEqual((code, calls, gaps), (0, ['start', 'verify', 'cleanup'], [(1, ['start'])]))
        self.assertTrue(report['complete'])

    def test_unknown_completion_preserves_without_cleanup(self):
        for stage in ('start', 'verify'):
            for failure in ('timeout', 'transport', 'interrupt'):
                with self.subTest(stage=stage, failure=failure):
                    code, calls, _, report = self.run_case(stage, failure)
                    self.assertNotEqual(code, 0)
                    self.assertNotIn('cleanup', calls)
                    self.assertTrue(report['cleanupDeferredUncertain'])

    def test_malformed_initial_proof_preserves(self):
        code, calls, _, report = self.run_case('start', 'malformed')
        self.assertNotEqual(code, 0)
        self.assertEqual(calls, ['start'])
        self.assertTrue(report['cleanupDeferredUncertain'])

    def test_completed_verify_failure_runs_only_owner_bound_cleanup(self):
        for failure in ('remote', 'malformed'):
            with self.subTest(failure=failure):
                code, calls, _, report = self.run_case('verify', failure)
                self.assertEqual(calls, ['start', 'verify', 'cleanup'])
                self.assertNotEqual(code, 0)
                self.assertFalse(report['passed'])
                self.assertTrue(report['cleanup']['currentOwnerStopProofVerified'])

    def test_cleanup_timeout_never_retries_removal(self):
        code, calls, _, report = self.run_case('cleanup', 'timeout')
        self.assertEqual(calls, ['start', 'verify', 'cleanup'])
        self.assertNotEqual(code, 0)
        self.assertTrue(report['cleanupDeferredUncertain'])


if __name__ == '__main__':
    unittest.main()
