"""Native helper protocol guards; only public synthetic fixtures are used."""
import json
import os
import shutil
import signal
import tempfile
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "target/debug/examples/v3_browser_interop"


@unittest.skipUnless(BINARY.is_file(), "build the native v3 fixture first")
class NativeBounds(unittest.TestCase):
    def run_peer(self, data):
        # The helper spawns no children. subprocess.run kills and reaps this
        # exact direct child on timeout; no shell or inherited credentials.
        return subprocess.run([str(BINARY)], input=data, capture_output=True,
                              env={}, timeout=5, check=False)

    def commands(self, values):
        result = self.run_peer(b"".join(json.dumps(v).encode()+b"\n" for v in values))
        return result, [json.loads(line) for line in result.stdout.splitlines()]

    def test_oversized_line_exits_without_reply(self):
        result = self.run_peer(b" "*(128*1024+1)+b"\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertLess(len(result.stderr), 100)

    def test_unknown_fields_and_large_frames_are_rejected(self):
        result, replies = self.commands([
            {"op":"fixtures", "extra":True},
            {"op":"read", "slot":"missing", "bytes":[0]*32769},
        ])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(replies == [{"error":True}, {"error":True}])

    def test_command_count_is_bounded(self):
        result, replies = self.commands([{"op":"write", "slot":"missing"}]*257)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(replies), 256)
        self.assertTrue(all(r == {"error":True} for r in replies))

    def test_bad_handshake_frame_fails_closed(self):
        result, replies = self.commands([
            {"op":"start", "slot":"abort", "case":"a-workspace", "side":"host"},
            {"op":"read", "slot":"abort", "bytes":[]},
            {"op":"write", "slot":"abort"},
        ])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(replies == [{"ok":[]}, {"error":True}, {"error":True}])


@unittest.skipUnless(BINARY.is_file() and (ROOT / "artifacts/crypto-v3-browser/wasm/lomi_remote_crypto.js").is_file() and shutil.which("node"), "build native and WASM fixtures first")
class NativeShutdown(unittest.TestCase):
    def shutdown_fault(self, hang):
        with tempfile.TemporaryDirectory(prefix="lomi-v3-shutdown-") as temporary:
            directory = Path(temporary)
            wrapper = directory / "peer"
            pid_file = directory / "pid"
            report_path = directory / "report.json"
            # Real native protocol/crypto runs unchanged. Fault only after its EOF
            # shutdown, so all browser assertions must have completed first.
            wrapper.write_text("#!/usr/bin/python3\nimport os, subprocess, time\n"
                + f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
                + f"result = subprocess.run([{str(BINARY)!r}], env={{}})\n"
                + "assert result.returncode == 0\n"
                + ("time.sleep(60)\n" if hang else "raise SystemExit(73)\n"))
            wrapper.chmod(0o700)
            process = subprocess.Popen([shutil.which("node"), str(ROOT / "tests/crypto-v3-browser/browser.mjs"),
                str(ROOT / "artifacts/crypto-v3-browser/wasm"), str(wrapper), str(report_path)],
                cwd=ROOT, env={}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                process.communicate(timeout=45)
                self.assertNotEqual(process.returncode, 0)
                report = json.loads(report_path.read_text())
                self.assertEqual(report["checks"], 79)
                self.assertFalse(report["passed"])
                self.assertFalse(report["cleanupCompleted"])
                self.assertIn("native peer did not exit cleanly", report["cleanupErrors"])
                self.assertTrue({"browser close", "browser server close", "HTTP close", "temporary profile removal"}.issubset(report["cleanupAttempts"]))
                self.assertEqual(report["nativeExit"], {"code": None if hang else 73,
                    "signal": "SIGKILL" if hang else None, "forcedTermination": hang})
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pid_file.read_text()), 0)
            finally:
                # On assertion or deadline failure, kill the entire owned group,
                # including a wrapper/native child; always reap the direct child.
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.communicate(timeout=5)

    def test_nonzero_after_eof_fails_proof_and_completes_cleanup(self):
        self.shutdown_fault(False)

    def test_eof_hang_is_killed_reaped_and_fails_proof(self):
        self.shutdown_fault(True)


if __name__ == "__main__":
    unittest.main()
