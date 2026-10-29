import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('windows_wasi', ROOT / 'tools/run_windows_git_wasi_spike.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class InventoryTests(unittest.TestCase):
    def test_explicit_archive_has_only_chosen_regular_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d / 'chosen').write_bytes(b'synthetic')
            (d / 'unrelated').write_bytes(b'not selected')
            result = runner.archive(d / 'out.tar.gz', {'fixture/.git/config': d / 'chosen'})
            self.assertEqual(list(result['files']), ['fixture/.git/config'])
            self.assertEqual(result['files']['fixture/.git/config']['bytes'], 9)

    def test_rejects_links_specials_and_parent_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d / 'file').write_text('synthetic')
            (d / 'link').symlink_to(d / 'file')
            os.mkfifo(d / 'fifo')
            for name in ['link', 'fifo']:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    runner.regular(d / name)
            with self.assertRaises(ValueError):
                runner.archive(d / 'out.tar.gz', {'../escape': d / 'file'})
            os.link(d / 'file', d / 'hardlink')
            with self.assertRaises(ValueError):
                runner.regular(d / 'hardlink')

    def test_tree_collection_rejects_symlink_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d / 'tree').mkdir()
            (d / 'tree/link').symlink_to(d, target_is_directory=True)
            with self.assertRaises(ValueError):
                runner.collect_tree(d / 'tree', 'snapshot', {})


class PreservationTests(unittest.TestCase):
    def evidence(self, d):
        return runner.Evidence(Path(d) / 'evidence.json', {'operations': []})

    def test_timeout_interrupt_transport_failure_prevent_next_command(self):
        for failure in [subprocess.TimeoutExpired('ssh', 1), KeyboardInterrupt(), subprocess.CompletedProcess('ssh', 255, '', '')]:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as d:
                e = self.evidence(d)
                with patch.object(runner, 'run_owned', side_effect=failure if isinstance(failure, BaseException) else None,
                                  return_value=failure) as command:
                    with self.assertRaises(BaseException):
                        e.command('first', ['ssh'], 1)
                    with self.assertRaises(RuntimeError):
                        e.command('second', ['ssh'], 1)
                self.assertEqual(command.call_count, 1)
                self.assertFalse(json.loads(e.path.read_text())['remoteCompletionKnown'])

    def test_completed_nonzero_can_be_observed_without_unknown_completion(self):
        with tempfile.TemporaryDirectory() as d:
            e = self.evidence(d)
            with patch.object(runner, 'run_owned', return_value=subprocess.CompletedProcess('ssh', 1, '', '')):
                with self.assertRaises(RuntimeError):
                    e.command('failed', ['ssh'], 1)
            self.assertTrue(e.known)

    def test_worker_unknown_envelopes_and_helper_failures_block_later_commands(self):
        cases = [
            (1, '{"completionKnown":false,"errorClass":"OwnedTreeTerminationRejected"}'),
            (1, '{"completionKnown":false,"errorClass":"OwnedOutputDrainUncertain"}'),
            (0, '{bad'),
            (0, '{"completionKnown":false}'),
            (0, '{"completionKnown":true,"timedOut":true}'),
        ]
        for code, output in cases:
            with self.subTest(code=code, output=output), tempfile.TemporaryDirectory() as d:
                e = self.evidence(d)
                with patch.object(runner, 'run_owned', return_value=subprocess.CompletedProcess('ssh', code, output, '')) as command:
                    with self.assertRaises((ValueError, RuntimeError)):
                        e.worker('worker', 'fixed', 1)
                    with self.assertRaises(RuntimeError):
                        e.command('later', ['ssh'], 1)
                self.assertEqual(command.call_count, 1)
                report = json.loads(e.path.read_text())
                self.assertFalse(report['remoteCompletionKnown'])
                self.assertFalse(report['operations'][0]['ownedWorkerCompletionKnown'])
                self.assertTrue(report['operations'][0]['transportCompletionKnown'])

    def test_verified_expected_trap_is_completed_worker(self):
        with tempfile.TemporaryDirectory() as d:
            e = self.evidence(d)
            envelope = dict(completionKnown=True, timedOut=False, outputOverflow=False,
                            exitCode=1, stdoutBase64='', stderrBase64='')
            with patch.object(runner, 'run_owned', return_value=subprocess.CompletedProcess('ssh', 0, json.dumps(envelope), '')):
                self.assertEqual(e.worker('expected-trap', 'fixed', 1)['exitCode'], 1)
            report = json.loads(e.path.read_text())
            self.assertTrue(report['remoteCompletionKnown'])
            self.assertTrue(report['operations'][0]['ownedWorkerCompletionKnown'])

    def test_windows_command_budget_checked_before_transport(self):
        with tempfile.TemporaryDirectory() as d:
            e = self.evidence(d)
            with patch.object(runner, 'run_owned') as command, self.assertRaises(ValueError):
                e.ps('oversized', 'x' * 10000)
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
