"""Synthetic environment and link rejection before integration source reads."""
from pathlib import Path
import tempfile
import unittest

from run_identity_admission_integration import checked_source_path


def verify_source_boundary():
    with tempfile.TemporaryDirectory(prefix='lomi-identity-source-boundary-') as directory:
        root = Path(directory).resolve()
        public = root / 'src/public.rs'
        public.parent.mkdir()
        public.write_text('public synthetic source')
        assert checked_source_path(root, 'src/public.rs') == public
        for name in ['src/.env', 'src/.env.production', 'src/env.private.py',
                     'src/local-db.env', 'src/private.env.local.py',
                     'src/private.env.dir/fixture.rs', 'src/.env.hidden/fixture.rs',
                     '../escape.rs', '/absolute.rs']:
            try:
                checked_source_path(root, name)
            except RuntimeError:
                pass
            else:
                raise AssertionError('private source name was accepted')
        private = root / 'private.env'
        private.write_text('synthetic sentinel; never read')
        (root / 'src/linked.rs').symlink_to(private)
        (root / 'linked').symlink_to(root / 'src', target_is_directory=True)
        for name in ['src/linked.rs', 'linked/public.rs']:
            try:
                checked_source_path(root, name)
            except RuntimeError:
                pass
            else:
                raise AssertionError('source link was accepted')


class SourceBoundaryTest(unittest.TestCase):
    def test_environment_and_link_sentinels(self):
        verify_source_boundary()


if __name__ == '__main__':
    unittest.main()
