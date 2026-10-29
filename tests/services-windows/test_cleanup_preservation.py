"""Exercise the real coordinator control flow without SSH or service operations."""
import base64
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_native


class CleanupPreservation(unittest.TestCase):
    def invoke(self, proof, failure=None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            artifacts = root / 'artifacts/windows'
            artifacts.mkdir(parents=True)
            snapshot = 'a' * 32
            (artifacts / ('prepare-' + snapshot + '.json')).write_text(json.dumps({
                'complete': True, 'source': {'sourceDirectory': r'C:\synthetic'},
                'sourceInventoryDigest': 'synthetic', 'archiveDigest': 'synthetic',
            }))
            commands = []
            native = {'passed': True, 'qualified': False,
                      'checks': [{'name': str(i), 'passed': True} for i in range(16)]}
            native.update(proof)

            def owned(argv, **kwargs):
                script = base64.b64decode(argv[-1]).decode('utf-16-le')
                commands.append(script)
                if "Test-Fixture.ps1'" in script:
                    # The state must have been persisted before SSH begins.
                    current = json.loads(next(artifacts.glob('native-*.json')).read_text())
                    self.assertIs(current['nativeTestAttempted'], True)
                    if failure == 'timeout':
                        raise subprocess.TimeoutExpired(argv, 240)
                    data = ''
                elif "Get-Content -LiteralPath" in script:
                    data = '{invalid' if failure == 'parse' else json.dumps(native)
                elif "Remove-Fixture.ps1'" in script:
                    data = json.dumps({'removed': True})
                elif 'ownedFixtureProcesses=' in script:
                    data = json.dumps({'serviceAbsent': True, 'privateUuidDirectoryAbsent': True, 'ownedFixtureProcesses': 0})
                elif "Install-Fixture.ps1'" in script:
                    if failure == 'install':
                        return subprocess.CompletedProcess(argv, 1, '', '')
                    data = '{}'
                elif 'Test-PolicyRegression.ps1' in script:
                    data = json.dumps({'passed': True, 'checks': list(range(4))})
                elif 'operatorSid=' in script:
                    data = json.dumps({'operatorSid': 'S-1-5-21-1-2-3-1000', 'admin': True})
                else:
                    data = '{}'
                return subprocess.CompletedProcess(argv, 0, data, '')

            with patch.object(run_native, 'ROOT', root), patch.object(run_native, 'run_owned', owned), \
                    patch.object(sys, 'argv', ['run_native.py', snapshot]), contextlib.redirect_stdout(io.StringIO()):
                code = run_native.main()
            result = json.loads(next(artifacts.glob('native-*.json')).read_text())
            removed = any("Remove-Fixture.ps1'" in script for script in commands)
            return code, result, removed

    def test_missing_cleanup_flag_preserves(self):
        code, result, removed = self.invoke({})
        self.assertEqual(code, 1)
        self.assertTrue(result['cleanupDeferredUncertain'])
        self.assertFalse(removed)

    def test_false_and_nonboolean_proof_preserve(self):
        for value in (False, None, 1, 'true'):
            with self.subTest(value=value):
                code, result, removed = self.invoke({'cleanupVerified': value})
                self.assertEqual(code, 1)
                self.assertTrue(result['cleanupDeferredUncertain'])
                self.assertFalse(removed)

    def test_ssh_timeout_preserves_even_without_native_report(self):
        code, result, removed = self.invoke({}, 'timeout')
        self.assertEqual(code, 1)
        self.assertTrue(result['cleanupDeferredUncertain'])
        self.assertFalse(removed)

    def test_parse_failure_preserves(self):
        code, result, removed = self.invoke({}, 'parse')
        self.assertEqual(code, 1)
        self.assertTrue(result['cleanupDeferredUncertain'])
        self.assertFalse(removed)

    def test_explicit_true_allows_verified_cleanup(self):
        code, result, removed = self.invoke({'cleanupVerified': True})
        self.assertEqual(code, 0)
        self.assertTrue(removed)
        self.assertTrue(result['aggregate']['cleanupAndIndependentAbsenceVerified'])

    def test_install_failure_before_native_attempt_still_cleans(self):
        code, result, removed = self.invoke({}, 'install')
        self.assertEqual(code, 1)
        self.assertTrue(removed)
        self.assertNotIn('cleanupDeferredUncertain', result)


if __name__ == '__main__':
    unittest.main()
