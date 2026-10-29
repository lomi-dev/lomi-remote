"""Run only in the disposable Linux VM; never print child streams or PIDs."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

worker = None


def live(pid):
    try:
        return Path('/proc', str(pid), 'stat').read_text().split(') ', 1)[1][0] != 'Z'
    except FileNotFoundError:
        return False


class Ownership(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if worker is None or not sys.platform.startswith('linux'):
            raise unittest.SkipTest('explicit owned worker path in disposable Linux VM required')

    def test_expected_nonzero_exit_is_known_and_captured(self):
        result = worker.run(['/usr/bin/python3', '-c', 'print("synthetic");raise SystemExit(7)'], os.getcwd(), 2, {})
        self.assertTrue(result['completionKnown'])
        self.assertEqual(result['exitCode'], 7)

    def test_deadline_kills_owned_descendant(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as directory:
            pidfile = Path(directory) / 'worker-pid'
            code = f'import subprocess,time,pathlib;p=subprocess.Popen(["/usr/bin/python3","-c","import time;time.sleep(60)"]);pathlib.Path({str(pidfile)!r}).write_text(str(p.pid));time.sleep(60)'
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                worker.run(['/usr/bin/python3', '-c', code], directory, 0.5, {})
            self.assertLess(time.monotonic() - started, 4)
            pid = int(pidfile.read_text())
            for _ in range(100):
                if not live(pid): break
                time.sleep(0.01)
            self.assertFalse(live(pid))

    def test_capture_bound_terminates_worker(self):
        with self.assertRaisesRegex(RuntimeError, 'capture bound'):
            worker.run(['/usr/bin/python3', '-c', 'import os;os.write(1,b"x"*200000)'], os.getcwd(), 2, {})

    def test_eof_success_cleans_remaining_owned_group_before_reap(self):
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as directory:
            pidfile = Path(directory) / 'worker-pid'
            code = f'import subprocess,pathlib;p=subprocess.Popen(["/usr/bin/python3","-c","import time;time.sleep(60)"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);pathlib.Path({str(pidfile)!r}).write_text(str(p.pid))'
            result = worker.run(['/usr/bin/python3', '-c', code], directory, 2, {})
            self.assertTrue(result['completionKnown'])
            pid = int(pidfile.read_text())
            for _ in range(100):
                if not live(pid): break
                time.sleep(0.01)
            self.assertFalse(live(pid))


if __name__ == '__main__':
    spec = importlib.util.spec_from_file_location('owned_fixture_worker', sys.argv.pop(1))
    worker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(worker)
    unittest.main()
