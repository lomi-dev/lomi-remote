"""Failure handling at the SSH install pipeline boundary."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import local_remote


class RemoteInstallTests(unittest.TestCase):
    def test_failed_curl_cannot_report_a_successful_empty_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            tools = home / ".local/bin"
            tools.mkdir(parents=True)
            curl = tools / "curl"
            curl.write_text("#!/bin/sh\nexit 22\n")
            curl.chmod(0o700)

            def run_locally(_host, _options, argv):
                return subprocess.run(argv, check=True, env=os.environ.copy(),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            with mock.patch.object(local_remote, "remote_home", return_value=str(home)), \
                    mock.patch.object(local_remote, "put_file"), \
                    mock.patch.object(local_remote, "remote_command", side_effect=run_locally):
                with self.assertRaises(subprocess.CalledProcessError) as failure:
                    local_remote.install_remote("test-user@192.168.1.192", [], home / "ca.pem",
                                                "https://127.0.0.1:18443/remote/releases/")
            self.assertEqual(failure.exception.returncode, 22)
