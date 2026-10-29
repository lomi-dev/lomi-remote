"""Bounded synthetic bridge tests. Never log helper traffic or private stderr."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("native_bridge", HERE / "bridge.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def exited(result):
    if result.stderr == "" and result.returncode == 1 and result.stdout == "":
        return True
    if result.stderr == "" and result.returncode == 0 and re.fullmatch(r"[ \t]*Zs?\+?[ \t]*\n?", result.stdout):
        return True
    raise AssertionError("process inspection did not prove exit")


class BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bridge.initialize_process_ownership()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nb-", dir="/tmp")
        self.home = Path(self.temp.name).resolve()
        self.home.chmod(0o700)
        self.instances = []
        self.overrides = patch.multiple(bridge, _IO_TIMEOUT=0.6, _IDLE_TIMEOUT=0.5, _CONNECT_TIMEOUT=5.0)
        self.overrides.start()

    def tearDown(self):
        for instance in self.instances:
            try:
                instance.close()
            except bridge.BridgeRejected:
                self.assertTrue(instance.closed)
        self.overrides.stop()
        self.temp.cleanup()

    def helper(self, mode="normal"):
        path = self.home / (mode + ".py")
        source = '''import json, os, pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_DFL)
mode = MODE
pathlib.Path(__file__).with_suffix('.pid').write_text(str(os.getpid())+' '+str(os.getpgrp()))
assert set(os.environ) <= {'HOME','TMPDIR','PATH','LANG','LC_CTYPE','__CF_USER_TEXT_ENCODING'}
assert pathlib.Path(os.environ['HOME']).stat().st_mode & 0o777 == 0o700
if mode == 'exit': os._exit(0)
if mode in ('stall', 'noread'):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline: time.sleep(0.02)
    os._exit(0)
for raw in sys.stdin.buffer:
    command=json.loads(raw)
    if mode == 'replystall':
        os.write(1,b'{\"ok\":true')
        time.sleep(10)
    if mode in ('stderr','stderrflood'):
        os.write(2,b'synthetic-private-stderr' if mode=='stderr' else b'x'*65536)
        time.sleep(10)
    if mode == 'oversized':
        sys.stdout.buffer.write(b'x'*(128*1024+1)+b'\\n');sys.stdout.buffer.flush();continue
    if mode == 'malformed':
        sys.stdout.buffer.write(b'{bad}\\n');sys.stdout.buffer.flush();continue
    if mode == 'extra':
        reply={'ok':True,'result':[],'unexpected':True}
    elif mode == 'wrongresult':
        reply={'ok':True,'result':{'unexpected':True}}
    elif mode == 'error':
        reply={'ok':False,'error':'NATIVE_FIXTURE_REJECTED'}
    elif mode == 'big':
        reply={'ok':True,'result':[255]*16512}
    elif command['op']=='write':
        reply={'ok':True,'result':[1,2,3]}
    else:
        reply={'ok':True,'result':[]}
    encoded=json.dumps(reply,separators=(',',':')).encode()+b'\\n'
    if mode == 'partial':
        for byte in encoded:
            os.write(1,bytes([byte]));time.sleep(0.001)
    else:
        os.write(1,encoded)
    if command['op']=='shutdown': break
'''.replace("MODE", repr(mode))
        path.write_text("#!" + str(Path(sys.executable).resolve()) + "\n" + source)
        path.chmod(0o700)
        return path

    def start(self, mode="normal"):
        binary = self.helper(mode)
        instance = bridge.NativeBridge(binary_path=binary, expected_sha256=bridge._sha256(binary), fixture_path=self.home)
        self.instances.append(instance)
        deadline = time.monotonic()+4
        while not binary.with_suffix(".pid").exists() and time.monotonic()<deadline:
            time.sleep(0.005)
        self.assertTrue(binary.with_suffix(".pid").is_file())
        return instance

    def connect(self, instance):
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        channel.settimeout(2)
        channel.connect(str(instance.socket_path))
        self.addCleanup(channel.close)
        return channel

    def receive(self, channel):
        data = bytearray()
        while not data.endswith(b"\n"):
            part = channel.recv(4096)
            if not part:
                return None
            data.extend(part)
            self.assertLessEqual(len(data), 128*1024)
        return json.loads(data)

    def wait_closed(self, instance):
        self.assertTrue(instance._closed.wait(6.5))
        self.assertTrue(instance.cleanup_complete)
        self.assertTrue(instance._child.returncode is not None)
        self.assertFalse(instance.socket_path.exists())

    def test_partial_request_response_and_final_direct_child_cleanup(self):
        instance = self.start("partial")
        channel = self.connect(instance)
        request = b'{"op":"write","slot":"synthetic"}\n'
        for part in (request[:3], request[3:11], request[11:]):
            channel.sendall(part)
            time.sleep(0.005)
        self.assertTrue(self.receive(channel) == {"ok":True,"result":[1,2,3]})
        # The next command is allowed only after the complete prior response.
        channel.sendall(request)
        self.assertTrue(self.receive(channel) == {"ok":True,"result":[1,2,3]})
        self.assertIsNone(instance._child.returncode)
        self.assertEqual(os.getpgid(instance._child.pid), os.getpgrp())
        self.assertEqual(stat.S_IMODE(instance.socket_path.stat().st_mode), 0o600)
        child = instance._child
        with patch.object(bridge.os, "kill", wraps=os.kill) as kills, patch.object(child, "wait", wraps=child.wait) as reap:
            instance.close()
            self.assertEqual(reap.call_count, 1)
            self.assertTrue(all(call.args[0] == child.pid for call in kills.call_args_list))
        self.wait_closed(instance)
        instance.close()  # Idempotent; never signal a previously reaped PID.

    def test_native_error_is_typed_and_does_not_queue_or_reopen(self):
        instance = self.start("error")
        channel = self.connect(instance)
        for _ in range(2):
            channel.sendall(b'{"op":"dispose","slot":"synthetic"}\n')
            self.assertTrue(self.receive(channel) == {"ok":False,"error":"NATIVE_FIXTURE_REJECTED"})
        channel.close()
        self.wait_closed(instance)
        self.assertTrue(instance.failed)

    def test_bad_requests_permanently_fail_closed(self):
        cases = [b'{bad}\n', b'{"op":"write","slot":"x","now":0}\n',
                 b'{"op":"write","op":"write","slot":"x"}\n',
                 b'{"op":"arbitrary_sign","bytes":[1]}\n',
                 b'{"op":"read","slot":"x","bytes":[true]}\n',
                 b'{"op":"write","slot":"x"}\n{"op":"write","slot":"x"}\n',
                 b'x'*(128*1024+1)]
        for index, request in enumerate(cases):
            with self.subTest(case=index):
                instance = self.start()
                channel = self.connect(instance)
                try:
                    channel.sendall(request)
                    rejected = self.receive(channel)
                    self.assertTrue(rejected is None or rejected == {"ok":False,"error":"BRIDGE_FIXTURE_REJECTED"})
                except (BrokenPipeError, ConnectionResetError):
                    pass
                self.wait_closed(instance)
                self.assertTrue(instance.failed)
                self.assertEqual(instance.command_count, 0)

    def test_oversized_partial_and_malformed_responses_fail_closed(self):
        for mode in ("oversized", "malformed", "extra", "wrongresult", "stderr", "stderrflood", "exit"):
            with self.subTest(mode=mode):
                instance = self.start(mode)
                try:
                    channel = self.connect(instance)
                    channel.sendall(b'{"op":"write","slot":"x"}\n')
                    self.receive(channel)
                except (ConnectionRefusedError, BrokenPipeError, ConnectionResetError, FileNotFoundError):
                    pass
                self.wait_closed(instance)
                self.assertTrue(instance.failed)
                if mode.startswith("stderr"):
                    self.assertTrue(0 < instance.stderr_byte_count <= 4096)

    def test_stalled_partial_request_and_helper_input_backpressure_have_deadlines(self):
        for mode, request in [("normal", b'{"op":'), ("replystall", b'{"op":"write","slot":"x"}\n'), ("noread", json.dumps({"op":"seal","slot":"x","bytes":[255]*16384}).encode()+b'\n')]:
            with self.subTest(mode=mode):
                instance = self.start(mode)
                channel = self.connect(instance)
                started = time.monotonic()
                channel.sendall(request)
                self.wait_closed(instance)
                self.assertLess(time.monotonic()-started, 1.5)
                self.assertTrue(instance.failed)

    def test_client_response_backpressure_has_deadline(self):
        instance = self.start("big")
        channel = self.connect(instance)
        # Force a small server send buffer; the client deliberately never reads.
        deadline = time.monotonic()+1
        while instance._client is None and time.monotonic()<deadline:
            time.sleep(0.005)
        self.assertIsNotNone(instance._client)
        instance._client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        with patch.object(bridge, "_response", wraps=bridge._response) as validated:
            channel.sendall(b'{"op":"seal","slot":"x","bytes":[1]}\n')
            self.wait_closed(instance)
            self.assertEqual(validated.call_count, 1)
        self.assertTrue(instance.failed)

    def test_queued_command_during_response_backpressure_is_terminal(self):
        instance = self.start("big")
        channel = self.connect(instance)
        deadline = time.monotonic()+1
        while instance._client is None and time.monotonic()<deadline:
            time.sleep(0.005)
        self.assertIsNotNone(instance._client)
        instance._client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
        blocked = bridge.threading.Event()
        original_wait = instance._wait
        def observe_wait(source, writing, deadline, **kwargs):
            if writing and source is instance._client:
                # Synchronize on actual kernel backpressure, not a timing guess.
                if not bridge.select.select([], [source], [], 0)[1]:
                    blocked.set()
            return original_wait(source, writing, deadline, **kwargs)
        with patch.object(bridge, "_IO_TIMEOUT", 2), patch.object(instance, "_wait", side_effect=observe_wait):
            request = b'{"op":"seal","slot":"x","bytes":[1]}\n'
            channel.sendall(request)
            self.assertTrue(blocked.wait(1))
            # Queue command two before reading any of response one. The old
            # bridge then completed both commands once this client drained it.
            channel.sendall(request)
            received = 0
            while True:
                try:
                    piece = channel.recv(4096)
                except ConnectionResetError:
                    break
                if not piece:
                    break
                received += len(piece)
                self.assertLessEqual(received, 3*bridge._MAX_LINE)
            self.wait_closed(instance)
        self.assertTrue(instance.failed)
        self.assertEqual(instance.command_count, 1)

    def test_bounded_command_count(self):
        with patch.object(bridge, "_MAX_COMMANDS", 2):
            instance = self.start()
            channel = self.connect(instance)
            for _ in range(2):
                channel.sendall(b'{"op":"dispose","slot":"x"}\n')
                self.assertTrue(self.receive(channel) == {"ok":True,"result":[]})
            self.wait_closed(instance)
            self.assertEqual(instance.command_count, 2)

    def test_eof_connect_and_idle_timeouts_are_terminal(self):
        for mode in ("eof", "connect", "idle"):
            with self.subTest(mode=mode):
                instance = self.start()
                if mode != "connect":
                    channel = self.connect(instance)
                    if mode == "eof":
                        channel.close()
                self.wait_closed(instance)
                self.assertTrue(instance.failed)

    def test_wrong_binary_hash_directory_mode_and_thread_are_rejected_before_spawn(self):
        binary = self.helper()
        with patch.object(bridge.subprocess, "Popen") as spawn:
            with self.assertRaises(bridge.BridgeRejected):
                bridge.NativeBridge(binary_path=binary, expected_sha256="0"*64, fixture_path=self.home)
            self.home.chmod(0o755)
            with self.assertRaises(bridge.BridgeRejected):
                bridge.NativeBridge(binary_path=binary, expected_sha256=bridge._sha256(binary), fixture_path=self.home)
            self.home.chmod(0o700)
            rejected = []
            def start():
                try:
                    bridge.NativeBridge(binary_path=binary, expected_sha256=bridge._sha256(binary), fixture_path=self.home)
                except bridge.BridgeRejected:
                    rejected.append(True)
            thread = bridge.threading.Thread(target=start)
            thread.start(); thread.join(1)
            self.assertTrue(rejected == [True])
            spawn.assert_not_called()

    def test_socket_replacement_and_changed_mode_are_retained(self):
        for replace in (True, False):
            with self.subTest(replace=replace):
                instance = self.start()
                replacement = None
                if replace:
                    instance.socket_path.unlink()
                    replacement = socket.socket(socket.AF_UNIX)
                    replacement.bind(str(instance.socket_path))
                    self.addCleanup(replacement.close)
                    instance.socket_path.chmod(0o600)
                else:
                    instance.socket_path.chmod(0o644)
                retained = instance.socket_path.lstat().st_ino
                with self.assertRaises(bridge.BridgeRejected):
                    instance.close()
                self.assertTrue(instance.closed)
                self.assertEqual(instance.socket_path.lstat().st_ino, retained)
                instance.socket_path.unlink()  # This test owns the replacement.

    def test_constructor_guard_failure_after_spawn_cleans_retained_child(self):
        binary = self.helper()
        expected = bridge._sha256(binary)
        children = []
        original = bridge.subprocess.Popen
        def spawn(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        with patch.object(bridge, "_sha256", side_effect=[expected,"0"*64]), patch.object(bridge.subprocess, "Popen", side_effect=spawn):
            with self.assertRaises(bridge.BridgeRejected):
                bridge.NativeBridge(binary_path=binary,expected_sha256=expected,fixture_path=self.home)
        self.assertTrue(len(children) == 1 and children[0].returncode is not None)
        self.assertFalse(list(self.home.glob("*.sock")))

    def test_directory_identity_change_retains_owned_socket(self):
        instance = self.start()
        self.home.chmod(0o750)
        try:
            with self.assertRaises(bridge.BridgeRejected):
                instance.close()
            self.assertTrue(instance.closed and instance.socket_path.exists())
            self.assertIsNotNone(instance._child.returncode)
        finally:
            self.home.chmod(0o700)
            instance.socket_path.unlink()

    def test_uncertain_child_identity_never_signals_or_unlinks_socket(self):
        instance = self.start()
        # Simulate loss of ownership without reaping/signalling this test child.
        original = bridge.owned.require_unreaped_child
        def uncertain(child):
            if child is instance._child:
                raise RuntimeError("synthetic ownership failure")
            return original(child)
        with patch.object(bridge.owned, "require_unreaped_child", uncertain), patch.object(bridge.os, "kill", wraps=os.kill) as kills:
            with self.assertRaises(bridge.BridgeRejected):
                instance.close()
            self.assertFalse(kills.called)
            self.assertTrue(instance.socket_path.exists())
        # Restore actual retained ownership to clean the synthetic child safely.
        original(instance._child)
        os.kill(instance._child.pid, signal.SIGKILL)
        for stream in (instance._child.stdin, instance._child.stdout, instance._child.stderr):
            stream.close()
        instance._child.wait(timeout=1)
        instance.socket_path.unlink()

    def test_inspector_rejects_error_status_and_ambiguous_output(self):
        valid = [(1,"",""), (0,"Z\n",""), (0," Z+ \n","")]
        invalid = [(2,"",""), (0,"",""), (1,"","error"), (0,"S\n",""),
                   (0,"Z\nZ\n",""), (0,"Z\nS\n",""), (0,"Zgarbage\n",""),
                   (0,"Z\n","warning"), (1,"Z\n",""), (0,"Z\n\n",""), (-9,"","")]
        for args in valid:
            self.assertTrue(exited(subprocess.CompletedProcess([],*args)))
        for args in invalid:
            with self.assertRaises(AssertionError):
                exited(subprocess.CompletedProcess([],*args))

    def test_outer_timeout_contains_both_processes_independently_of_eof(self):
        helper = self.helper("stall")
        wrapper = self.home / "outer.py"
        marker = self.home / "outer.pid"
        wrapper.write_text(
            "import importlib.util,os,pathlib,time\n"
            f"s=importlib.util.spec_from_file_location('b',{str(HERE/'bridge.py')!r})\n"
            "b=importlib.util.module_from_spec(s);s.loader.exec_module(b)\n"
            "b.initialize_process_ownership()\n"
            f"x=b.NativeBridge(binary_path=pathlib.Path({str(helper)!r}),expected_sha256={bridge._sha256(helper)!r},fixture_path=pathlib.Path({str(self.home)!r}))\n"
            f"pathlib.Path({str(marker)!r}).write_text(str(os.getpid())+' '+str(os.getpgrp()))\n"
            "while True: time.sleep(1)\n")
        env = {"HOME":str(self.home),"TMPDIR":str(self.home),"PATH":"/usr/bin:/bin","LANG":"C","PYTHONDONTWRITEBYTECODE":"1"}
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            bridge.owned.run_owned([sys.executable,str(wrapper)],cwd=self.home,env=env,timeout=3)
        markers = [list(map(int,path.read_text().split())) for path in (marker,helper.with_suffix('.pid'))]
        self.assertTrue(all(len(m)==2 and m[1]==markers[0][0] for m in markers))
        for pid, _ in markers:
            result = bridge.owned.run_owned(["/bin/ps","-o","stat=","-p",str(pid)],cwd=self.home,env=env,timeout=1)
            self.assertTrue(exited(result))
        self.assertLess(time.monotonic()-started,5)  # Below helper's 10s failsafe.

    def test_actual_guarded_native_public_init_and_shutdown(self):
        binary = HERE.parents[1] / "target/debug/examples/transport_authority"
        expected = "7ff6f31b379264c2be7cd3cdab00ed467bde1c604ca2379f24eab5f77565e0a5"
        if not binary.is_file():
            self.skipTest("already-built guarded native binary unavailable")
        instance = bridge.NativeBridge(binary_path=binary,expected_sha256=expected,fixture_path=self.home)
        self.instances.append(instance)
        channel = self.connect(instance)
        channel.sendall(json.dumps({"op":"init","account_id":[1]*16,"host_id":[2]*16,"window_id":[3]*16}).encode()+b'\n')
        response = self.receive(channel)
        self.assertTrue(response is not None and response.get("ok") is True)
        self.assertTrue(response["result"]["hostPin"] != response["result"]["consumerPin"])
        channel.sendall(b'{"op":"shutdown"}\n')
        self.assertTrue(self.receive(channel) == {"ok":True,"result":[]})
        self.wait_closed(instance)
        self.assertFalse(instance.failed)


if __name__ == "__main__":
    unittest.main()
