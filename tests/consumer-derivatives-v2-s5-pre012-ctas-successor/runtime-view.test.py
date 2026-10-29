import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import uuid
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('runtime_view', HERE / 'runtime-view.py')
runtime_view = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime_view)
SOURCE = runtime_view.TOOLCHAIN
BASE_LOCK = json.loads(runtime_view.BASE_LOCK.read_bytes())


class RuntimeViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_temp = tempfile.TemporaryDirectory(dir=HERE)
        cls.original_source = runtime_view.TOOLCHAIN
        cls.source_root = Path(cls.source_temp.name) / '18'
        (cls.source_root / 'lib').mkdir(parents=True)
        (cls.source_root / 'bin').mkdir()
        for relative in (set(BASE_LOCK['toolchainCoreSha256']) |
                         set(BASE_LOCK['toolchainInitdbSha256'])):
            source = cls.original_source / relative.removeprefix('Contents/Versions/18/')
            target = cls.source_root / relative.removeprefix('Contents/Versions/18/')
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copyfile(source, target)
        for alias, basename in runtime_view.PLAN['aliases'].items():
            (cls.source_root / 'lib' / alias).symlink_to(basename)
        shutil.copytree(cls.original_source / 'share/postgresql', cls.source_root / 'share/postgresql',
                        symlinks=True, dirs_exist_ok=True)
        runtime_view.TOOLCHAIN = cls.source_root
        global SOURCE
        SOURCE = cls.source_root

    @classmethod
    def tearDownClass(cls):
        runtime_view.TOOLCHAIN = cls.original_source
        cls.source_temp.cleanup()

    def make_view(self):
        view = HERE / ('.ctas-runner-view-' + uuid.uuid4().hex)
        view.mkdir(mode=0o700)
        app = view / BASE_LOCK['toolchainRoot'] / 'Postgres.app'
        for relative, digest in BASE_LOCK['toolchainCoreSha256'].items():
            target = app / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            source = SOURCE / relative.removeprefix('Contents/Versions/18/')
            shutil.copyfile(source, target)
            target.chmod(0o444)
        for relative, digest in BASE_LOCK['toolchainInitdbSha256'].items():
            target = app / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            source = SOURCE / relative.removeprefix('Contents/Versions/18/')
            shutil.copyfile(source, target)
            target.chmod(0o444)
        for directory in sorted((path for path in app.rglob('*') if path.is_dir()),
                                key=lambda path: len(path.parts), reverse=True):
            directory.chmod(0o700)
        app.chmod(0o700)
        return view

    def test_prepares_exact_aliases_and_modes(self):
        view = self.make_view()
        try:
            result = runtime_view.prepare(view)
            self.assertEqual(result['aliases'], 14)
            app = view / BASE_LOCK['toolchainRoot'] / 'Postgres.app'
            self.assertTrue((app / 'Contents/Versions/18/lib/libzstd.1.dylib').is_symlink())
            self.assertFalse((view / 'Contents/Versions/18/lib/libzstd.1.dylib').exists())
            for alias, target in runtime_view.PLAN['aliases'].items():
                self.assertTrue((app / 'Contents/Versions/18/lib' / alias).is_symlink())
                self.assertEqual((app / 'Contents/Versions/18/lib' / alias).readlink().as_posix(), target)
            for relative in runtime_view.PLAN['executables']:
                self.assertEqual((app / relative).stat().st_mode & 0o777, 0o555)
            self.assertEqual(result['shareEntries'], len(runtime_view._load_share_manifest()))
            manifest = runtime_view._load_share_manifest()
            self.assertEqual((sum(item['type'] == 'directory' for item in manifest.values()),
                              sum(item['type'] == 'file' for item in manifest.values()),
                              sum(item['type'] == 'symlink' for item in manifest.values())),
                             (26, 1027, 875))
            share = app / 'Contents/Versions/18/share/postgresql'
            self.assertEqual(runtime_view._scan_tree(share), manifest)
            for relative, item in manifest.items():
                target = share / relative
                if item['type'] == 'directory':
                    self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                elif item['type'] == 'file':
                    self.assertEqual(target.stat().st_mode & 0o777, 0o444)
            for relative in ('timezone/Europe/Warsaw', 'postgresql.conf.sample',
                             'extension/plpgsql.control'):
                target = app / 'Contents/Versions/18/share/postgresql' / relative
                self.assertTrue(target.is_file())
                self.assertEqual(target.stat().st_mode & 0o777, 0o444)
            for relative, item in manifest.items():
                target = app / 'Contents/Versions/18/share/postgresql' / relative
                if item['type'] == 'symlink':
                    self.assertTrue(target.is_symlink())
                    self.assertEqual(target.readlink().as_posix(), item['target'])
        finally:
            shutil.rmtree(view)

    def test_rejects_tampered_target_and_unsafe_destination(self):
        view = self.make_view()
        try:
            target = (view / BASE_LOCK['toolchainRoot'] / 'Postgres.app' /
                      'Contents/Versions/18/lib/libzstd.1.5.7.dylib')
            target.chmod(0o644)
            target.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'private view target hash mismatch'):
                runtime_view.prepare(view)
            with self.assertRaisesRegex(ValueError, 'UUID-named direct child'):
                runtime_view.prepare(HERE / 'outside')
        finally:
            shutil.rmtree(view)

    def test_rejects_unprivate_or_unowned_view(self):
        view = self.make_view()
        try:
            view.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'mode 0700'):
                runtime_view.prepare(view)
            view.chmod(0o700)
            with mock.patch.object(runtime_view.os, 'getuid', return_value=view.stat().st_uid + 1):
                with self.assertRaisesRegex(ValueError, 'owned by current user'):
                    runtime_view.prepare(view)
        finally:
            shutil.rmtree(view)

    def test_rejects_in_view_parent_symlink_before_outside_mutation(self):
        view = self.make_view()
        with tempfile.TemporaryDirectory(dir=HERE) as temporary:
            outside = Path(temporary)
            sentinel = outside / 'sentinel'
            sentinel.write_bytes(b'untouched')
            sentinel.chmod(0o444)
            try:
                app = view / BASE_LOCK['toolchainRoot'] / 'Postgres.app'
                shutil.rmtree(app / 'Contents')
                (app / 'Contents').symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, 'symlink component'):
                    runtime_view.prepare(view)
                self.assertEqual(sentinel.read_bytes(), b'untouched')
                self.assertEqual(sentinel.stat().st_mode & 0o777, 0o444)
            finally:
                shutil.rmtree(view)

    def test_rejects_share_collision_before_other_mutations(self):
        view = self.make_view()
        try:
            app = view / BASE_LOCK['toolchainRoot'] / 'Postgres.app'
            relative = 'Contents/Versions/18/share/postgresql/postgresql.conf.sample'
            target = app / relative
            target.write_bytes(b'wrong collision')
            with self.assertRaisesRegex(ValueError, 'private share tree collision'):
                runtime_view.prepare(view)
            self.assertEqual((app / 'Contents/Versions/18/bin/postgres').stat().st_mode & 0o777, 0o444)
            self.assertFalse((app / 'Contents/Versions/18/lib/libzstd.1.dylib').exists())
        finally:
            shutil.rmtree(view)

    def test_rejects_extra_missing_and_unsafe_source_entries_before_mutation(self):
        view = self.make_view()
        share = SOURCE / 'share/postgresql'
        sentinel = Path(self.source_temp.name) / 'outside-sentinel'
        sentinel.write_bytes(b'untouched')
        try:
            extra = share / 'unexpected.extra'
            extra.write_bytes(b'extra')
            with self.assertRaisesRegex(ValueError, 'differs from pinned manifest'):
                runtime_view.prepare(view)
            extra.unlink()

            missing = share / 'postgresql.conf.sample'
            backup = share / 'postgresql.conf.sample.saved'
            missing.rename(backup)
            with self.assertRaisesRegex(ValueError, 'differs from pinned manifest'):
                runtime_view.prepare(view)
            backup.rename(missing)

            link = share / 'extension/address_standardizer--2.0.0--ANY.sql'
            target = link.readlink()
            link.unlink()
            link.symlink_to('../../../../outside-sentinel')
            with self.assertRaisesRegex(ValueError, 'differs from pinned manifest'):
                runtime_view.prepare(view)
            link.unlink()
            link.symlink_to(target)

            app = view / BASE_LOCK['toolchainRoot'] / 'Postgres.app'
            self.assertFalse((app / 'Contents/Versions/18/lib/libzstd.1.dylib').exists())
            self.assertEqual(sentinel.read_bytes(), b'untouched')
        finally:
            shutil.rmtree(view)


if __name__ == '__main__':
    unittest.main()
