import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).parent))
import build_receipt
spec = importlib.util.spec_from_file_location('desktop_runner', REPO / 'tools/run_desktop_e0.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CleanupTests(unittest.TestCase):
    def test_stop_and_removal_faults_still_attempt_all_cleanup_and_save_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / 'home'
            appdata = home / 'appdata'
            appdata.mkdir(parents=True)
            children = [Mock(stdin=None), Mock(), Mock()]
            for child in children:
                child.poll.return_value = 0
            report = {'status': 'passed', 'primaryEvidence': 'retained'}
            original_remove = runner.shutil.rmtree
            def remove(path):
                if path == appdata:
                    raise OSError('injected appdata removal fault')
                original_remove(path)
            with patch.object(runner, 'stop', side_effect=[OSError('injected stop fault'), None, None]) as stop, patch.object(runner.shutil, 'rmtree', side_effect=remove):
                runner.cleanup_fixture(report, root, appdata, home, children, [])
            self.assertEqual(stop.call_count, 3)
            saved = json.loads((root / 'result.json').read_text())
            self.assertEqual(saved['status'], 'failed')
            self.assertEqual(saved['primaryEvidence'], 'retained')
            self.assertEqual(len(saved['cleanup']['errors']), 2)
            self.assertTrue(saved['cleanup']['privateHomeRemoved'])


class BindingTests(unittest.TestCase):
    def test_external_link_contents_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dependencies = root / 'node_modules'
            dependencies.mkdir()
            package = root / 'external-package'
            package.mkdir()
            source = package / 'index.js'
            source.write_text('export const value = 1')
            (dependencies / 'package').symlink_to(package, target_is_directory=True)
            before = build_receipt.dependency_digest(dependencies)
            source.write_text('export const value = 2')
            self.assertNotEqual(before, build_receipt.dependency_digest(dependencies))

    def test_changed_frontend_domain_and_binary_reject_existing_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'binary'
            binary.write_bytes(b'controlled build')
            binaries = {'desktop': binary, 'domain': binary}
            inputs = {'sources': {'desktop/src/model.ts': 'old', 'crates/lomi-domain-spike/src/lib.rs': 'old'}}
            checks = [{'command': [str(i)], 'exitCode': 0} for i in range(3)]
            receipt = root / 'receipt.json'
            receipt.write_text(json.dumps(build_receipt.receipt(inputs, binaries, checks)))
            build_receipt.verify(receipt, inputs, binaries, checks)
            for name in inputs['sources']:
                changed = {'sources': {**inputs['sources'], name: 'changed'}}
                with self.assertRaises(RuntimeError):
                    build_receipt.verify(receipt, changed, binaries, checks)
            binary.write_bytes(b'arbitrary old executable')
            with self.assertRaises(RuntimeError):
                build_receipt.verify(receipt, inputs, binaries, checks)

    def test_arbitrary_checkout_edit_is_rejected_before_launch(self):
        checkout = REPO / 'artifacts/e0-desktop-checkout'
        source = checkout / 'src/model.ts'
        original = source.read_bytes()
        try:
            source.write_bytes(original + b'\n// injected unrelated edit\n')
            with self.assertRaisesRegex(RuntimeError, 'Unexpected desktop source edits'):
                build_receipt.exact_checkout(REPO, checkout)
        finally:
            source.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
