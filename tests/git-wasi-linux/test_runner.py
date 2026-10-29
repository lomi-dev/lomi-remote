import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import hashlib
import io
import sys
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('linux_wasi', ROOT / 'tools/run_linux_git_wasi_spike.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class Harness(unittest.TestCase):
    def evidence(self, directory):
        return runner.Evidence(Path(directory) / 'evidence.json', {'operations': []})

    def test_inventory_regular_only_and_safe_archive_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'file').write_bytes(b'synthetic')
            (root / 'link').symlink_to(root / 'file')
            with self.assertRaises(ValueError):
                runner.regular(root / 'link')
            with self.assertRaises(ValueError):
                runner.pack(root / 'out.tar.gz', {'../escape': root / 'file'})
            result = runner.pack(root / 'out.tar.gz', {'snapshot/.git/config': root / 'file'})
            self.assertEqual(list(result['files']), ['snapshot/.git/config'])

    def test_transport_timeout_interrupt_and_nonzero_block_future_commands(self):
        for failure in [subprocess.TimeoutExpired('lima', 1), KeyboardInterrupt(), subprocess.CompletedProcess('lima', 1, '', '')]:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                e = self.evidence(directory)
                with patch.object(runner, 'run_owned', side_effect=failure if isinstance(failure, BaseException) else None,
                                  return_value=failure) as command:
                    with self.assertRaises(BaseException):
                        e.command('first', ['lima'], 1)
                    with self.assertRaises(RuntimeError):
                        e.command('second', ['lima'], 1)
                self.assertEqual(command.call_count, 1)
                self.assertFalse(json.loads(e.path.read_text())['remoteCompletionKnown'])

    def test_worker_false_malformed_or_nonzero_cannot_claim_completion(self):
        for code, output in [(0, '{bad'), (0, '{"completionKnown":false}'), (1, '{"completionKnown":false,"errorClass":"TimeoutError"}')]:
            with self.subTest(code=code, output=output), tempfile.TemporaryDirectory() as directory:
                e = self.evidence(directory)
                request = {'timeoutSeconds': 1}
                responses = [subprocess.CompletedProcess('lima', 0, '{"written":true}', ''),
                             subprocess.CompletedProcess('lima', code, output, '')]
                with patch.object(runner, 'run_owned', side_effect=responses) as command:
                    with self.assertRaises((ValueError, RuntimeError)):
                        e.worker('worker', '/fixed', request)
                    with self.assertRaises(RuntimeError):
                        e.command('later', ['lima'], 1)
                self.assertEqual(command.call_count, 2)
                report = json.loads(e.path.read_text())
                self.assertFalse(report['remoteCompletionKnown'])
                self.assertFalse(report['operations'][-1]['workerCompletionKnown'])

    def test_verified_expected_trap_is_completed_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            e = self.evidence(directory)
            envelope = dict(completionKnown=True, exitCode=1, stdoutBase64='', stderrBase64='')
            responses = [subprocess.CompletedProcess('lima', 0, '{"written":true}', ''),
                         subprocess.CompletedProcess('lima', 0, json.dumps(envelope), '')]
            with patch.object(runner, 'run_owned', side_effect=responses):
                self.assertEqual(e.worker('trap', '/fixed', {'timeoutSeconds': 1})['exitCode'], 1)
            self.assertTrue(json.loads(e.path.read_text())['operations'][-1]['workerCompletionKnown'])

    def test_optimized_python_cannot_bypass_digest_paths_or_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'fixture'
            source.mkdir()
            (source / 'file').write_bytes(b'synthetic')
            expected = {'file': {'bytes': 9, 'sha256': hashlib.sha256(b'synthetic').hexdigest()}}
            good = subprocess.run([sys.executable, '-O', '-c', runner.inventory_code(str(source), expected)], capture_output=True)
            self.assertEqual(good.returncode, 0)
            (source / 'unexpected').write_bytes(b'additional')
            bad = subprocess.run([sys.executable, '-O', '-c', runner.inventory_code(str(source), expected)], capture_output=True)
            self.assertNotEqual(bad.returncode, 0)
            (source / 'unexpected').unlink()
            (source / 'link').symlink_to(source / 'file')
            changed_link = runner.inventory_code(str(source), expected, {'link': str(source / 'other')})
            self.assertNotEqual(subprocess.run([sys.executable, '-O', '-c', changed_link], capture_output=True).returncode, 0)
            archive = root / 'bad.tar.gz'
            with tarfile.open(archive, 'w:gz') as out:
                entry = tarfile.TarInfo('../escape')
                entry.size = 3
                out.addfile(entry, io.BytesIO(b'bad'))
            actual_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            for name, digest in [('bad-digest', 'incorrect'), ('unsafe-member', actual_digest)]:
                code = runner.extract_code(str(archive), str(root / name), digest)
                self.assertNotEqual(subprocess.run([sys.executable, '-O', '-c', code], capture_output=True).returncode, 0)
            self.assertFalse((root / 'escape').exists())

    def test_generated_python_commands_parse(self):
        compile(runner.extract_code('/new.tar.gz', '/new', 'digest'), '<extract>', 'exec')
        compile(runner.inventory_code('/new', {'file': {'bytes': 1, 'sha256': 'digest'}}), '<inventory>', 'exec')


if __name__ == '__main__':
    unittest.main()
