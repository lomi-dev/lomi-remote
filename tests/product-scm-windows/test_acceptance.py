"""Reject a green aggregate when required native cleanup evidence is false."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from run_native import (ROOT, require_native_pass, public_dependency_closure,
                       subset_metadata_command, verify_subset_lock, Evidence)


def complete_receipt():
    return dict(passed=True, serviceAbsent=True, profileRootAbsent=True,
                controlledJobTreeGone=True, crashedJobTreeGone=True,
                sentinelPreserved=True, foreignAccountRejected=True,
                ownedProcessesRemaining=0,
                observerExample=dict(passed=True,twoClients=True,ptyInput=True,
                                     ptyResize=True,ptyCtrlC=True,
                                     dpapiSameAccountRoundtrip=True,consoleAttached=False),
                actualCliEntry=dict(running=True,controlledStop=True,crashNonzero=True,restart=True),
                productionTimeout=dict(processExitCode=1, scmFailed=True,
                                       ownedTreeGone=True, realScmStop=True),
                restart=dict(oldSessionLost=True, automaticShell=False,
                             inputReplayed=False))


class NativeAcceptance(unittest.TestCase):
    def test_nested_worker_failure_is_recorded_separately_from_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = {'operations': [], 'remoteCompletionKnown': True}
            evidence = Evidence(Path(temporary) / 'report.json', report)

            def completed_transport(self, name, script, timeout=120, *, owned_worker=False):
                report['operations'].append({'name': name, 'exitCode': 0,
                                             'completionKnown': True, 'passed': True})
                return json.dumps({'completionKnown': True, 'timedOut': False,
                                   'outputOverflow': False, 'exitCode': 101,
                                   'stdoutBase64': '', 'stderrBase64': ''})

            with mock.patch.object(Evidence, 'ps', completed_transport):
                result = evidence.worker('native-clippy', 'bounded script', 320)

            self.assertEqual(result['exitCode'], 101)
            operation = report['operations'][0]
            self.assertEqual(operation['exitCode'], 0)  # SSH/PowerShell transport
            self.assertEqual(operation['workerExitCode'], 101)
            self.assertTrue(operation['ownedWorkerCompletionKnown'])
            self.assertTrue(operation['completionKnown'])
            self.assertFalse(operation['workerPassed'])
            self.assertTrue(operation['passed'])  # transport itself completed

    def test_fresh_cache_resolution_still_rejects_lock_identity_changes(self):
        command = subset_metadata_command(ROOT / 'Cargo.toml')
        self.assertNotIn('--offline', command)
        locked = '[[package]]\nname = "sample"\nversion = "1.0.0"\nsource = "registry+https://example.invalid"\nchecksum = "abc"\n'
        changed = locked.replace('checksum = "abc"', 'checksum = "def"')
        with self.assertRaises(RuntimeError):
            verify_subset_lock(locked, changed)

    def test_frozen_inputs_cover_current_product_closure_and_scm_example(self):
        files, packages = public_dependency_closure(
            ROOT, ('crates/lomiremote', 'crates/lomi-host', 'crates/lomi-platform'))
        self.assertIn('crates/lomi-files', packages)
        self.assertIn('crates/lomiremote/examples/windows-scm-proof.rs', files)

    def test_complete_receipt_is_accepted(self):
        require_native_pass(complete_receipt())

    def test_claimed_pass_cannot_hide_failed_or_missing_cleanup(self):
        for field in ('serviceAbsent', 'profileRootAbsent', 'controlledJobTreeGone',
                      'crashedJobTreeGone', 'sentinelPreserved', 'foreignAccountRejected'):
            for value in (False, None):
                with self.subTest(field=field, value=value):
                    receipt = complete_receipt()
                    receipt[field] = value
                    with self.assertRaises(RuntimeError):
                        require_native_pass(receipt)

    def test_exit_zero_and_incomplete_process_evidence_are_rejected(self):
        for value in (0, None, True):
            receipt = complete_receipt()
            receipt['productionTimeout']['processExitCode'] = value
            with self.assertRaises(RuntimeError):
                require_native_pass(receipt)
        for value in (1, None, False):
            receipt = complete_receipt()
            receipt['ownedProcessesRemaining'] = value
            with self.assertRaises(RuntimeError):
                require_native_pass(receipt)

    def test_automatic_shell_or_input_replay_are_rejected(self):
        for field in ('automaticShell', 'inputReplayed'):
            receipt = copy.deepcopy(complete_receipt())
            receipt['restart'][field] = True
            with self.assertRaises(RuntimeError):
                require_native_pass(receipt)


if __name__ == '__main__':
    unittest.main()
