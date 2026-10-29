"""Focused archive boundary and source-corruption tests; no Cargo compilation."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

import package_authority_crypto as packer


class PackageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files, cls.provenance = packer.verified_files()

    def test_archive_is_deterministic_and_has_only_verified_regular_files(self):
        payload = packer.tarball(self.files)
        self.assertEqual(payload, packer.tarball(dict(reversed(list(self.files.items())))))
        self.assertEqual(payload[4:8], bytes(4))  # Gzip timestamp.
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
            members = archive.getmembers()
            expected = {f'package/{name}': content for name, content in self.files.items()}
            self.assertEqual([m.name for m in members], sorted(expected))
            for member in members:
                self.assertTrue(member.isfile())
                self.assertEqual((member.mode, member.uid, member.gid, member.mtime), (0o644, 0, 0, 0))
                content = archive.extractfile(member).read()
                self.assertEqual(content, expected[member.name])
                relative = member.name.removeprefix('package/generated/')
                if relative in self.provenance['generatedSha256']:
                    self.assertEqual(hashlib.sha256(content).hexdigest(), self.provenance['generatedSha256'][relative])
        self.assertLess(len(gzip.decompress(payload)), packer.MAX_TOTAL)

    def workspace_copy(self, destination):
        for relative in self.provenance['sourceSha256']:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(packer.ROOT / relative, target)
        shutil.copytree(packer.ROOT / packer.PACKAGE / 'generated', destination / packer.PACKAGE / 'generated')

    def test_corrupt_source_and_unexpected_generated_file_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.workspace_copy(root)
            packer.verified_files(root)
            source = root / packer.PACKAGE / 'src/index.mjs'
            original = source.read_bytes()
            source.write_bytes(original + b'\n// altered\n')
            with self.assertRaisesRegex(ValueError, 'source provenance mismatch'):
                packer.verified_files(root)
            source.write_bytes(original)
            extra = root / packer.PACKAGE / 'generated/unexpected.mjs'
            extra.write_text('export const fixture = true;')
            with self.assertRaisesRegex(ValueError, 'unexpected generated'):
                packer.verified_files(root)

    def test_link_and_fifo_are_refused_without_reading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'source'
            source.write_bytes(b'known')
            link = root / 'link'
            link.symlink_to(source)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                packer.regular(link)
            import os
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, 'bounded regular'):
                packer.regular(fifo)

    def test_notices_preserve_actual_license_text_and_pinned_snow(self):
        notices = json.loads(self.files['THIRD_PARTY_NOTICES.json'])
        self.assertEqual(notices['cargoLockSha256'], self.provenance['sourceSha256']['Cargo.lock'])
        snow = [p for p in notices['packages'] if p['name'] == 'snow']
        self.assertEqual(len(snow), 1)
        self.assertEqual(snow[0]['version'], '0.10.0')
        self.assertEqual(snow[0]['source'], 'crates/lomi-remote-crypto/vendor/snow')
        for package in notices['packages']:
            for license in package['licenseFiles']:
                self.assertEqual(hashlib.sha256(license['text'].encode()).hexdigest(), license['sha256'])
        for license in snow[0]['licenseFiles']:
            self.assertEqual(license['text'].encode(), (packer.ROOT / snow[0]['source'] / license['path']).read_bytes())

    def test_existing_artifact_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'artifact'
            packer.write_immutable(path, b'first')
            packer.write_immutable(path, b'first')
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                packer.write_immutable(path, b'other')
            self.assertEqual(path.read_bytes(), b'first')


if __name__ == '__main__':
    unittest.main()
