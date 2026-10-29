"""Private synthetic native-helper bridge; no product or general signer API.

On the main thread, call initialize_process_ownership() before any harness
children/threads, then construct NativeBridge with an exact guarded binary and
an existing owned 0700 fixture directory (short enough for an AF_UNIX pathname).
Use one persistent socket client, one command followed by one response. EOF,
pipelining, malformed input/output and deadlines permanently close the bridge.
The harness owns the outer process group; this module never signals that group.
Only the retained direct child is signalled during final cleanup. Keep the
parent's owned group alive through cleanup. NativeBridge.close() is mandatory.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid

_ROOT = Path(__file__).resolve().parents[2]
_OWNED_PATH = _ROOT / "tools/owned_process.py"
# Share the parent's already initialized owned_process module when it imported
# the same file under another name. Never reset SIGCHLD behind a parent's back.
owned = next((m for m in tuple(sys.modules.values())
              if os.path.basename(getattr(m, "__file__", "") or "") == "owned_process.py"
              and Path(m.__file__).resolve() == _OWNED_PATH), None)
if owned is None:
    _spec = importlib.util.spec_from_file_location("_lomi_bridge_owned_process", _OWNED_PATH)
    owned = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = owned
    _spec.loader.exec_module(owned)

_MAX_LINE = 128 * 1024
_MAX_COMMANDS = 8192
_IO_TIMEOUT = 5.0
_IDLE_TIMEOUT = 60.0
_CONNECT_TIMEOUT = 5.0
_TICK = 0.05
_ERROR = b'{"ok":false,"error":"BRIDGE_FIXTURE_REJECTED"}\n'


class BridgeRejected(RuntimeError):
    def __init__(self):
        super().__init__("BRIDGE_FIXTURE_REJECTED")


def initialize_process_ownership():
    """Parent startup only; invoke before any children or extra threads exist."""
    if threading.current_thread() is not threading.main_thread():
        raise BridgeRejected()
    owned.initialize_process_ownership()


def _require(condition):
    if not condition:
        raise BridgeRejected()


def _object(value, keys):
    _require(type(value) is dict and set(value) == set(keys.split()))


def _text(value, maximum):
    _require(type(value) is str and 0 < len(value) <= maximum and value.isascii())


def _bytes(value, maximum, exact=None):
    _require(type(value) is list and len(value) <= maximum
             and (exact is None or len(value) == exact)
             and all(type(x) is int and 0 <= x <= 255 for x in value))


def _decimal(value):
    _require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value)
             and int(value) <= 2**64 - 1)


def _wire(value):
    _object(value, "canonicalCbor signature")
    for key, limit in [("canonicalCbor", 64 * 1024), ("signature", 128)]:
        item = value[key]
        _require(type(item) is str and 0 < len(item) <= limit and len(item) % 2 == 0
                 and re.fullmatch(r"[0-9a-f]+", item))
    _require(len(value["signature"]) == 128)


def _terminal(value):
    if value is None:
        return
    _object(value, "paneId sessionId sessionEpoch terminalProfile")
    for key in ("paneId", "sessionId", "sessionEpoch"):
        _bytes(value[key], 16, 16)
    _require(value["terminalProfile"] == "lomi-rust-grid-v1-experimental")


def _grant(value):
    _object(value, "version apiMajor applicationMajor accountId hostId hostFingerprint hostAuthorizationId accessEpoch consumerAuthorizationId accountSessionId consumerId consumerFingerprint grantId grantRevision workspaceId workspaceEpoch runtimeId runtimeGeneration capabilities nonce expiresAt purpose")
    _require(type(value["version"]) is int and value["version"] == 3
             and type(value["apiMajor"]) is int and value["apiMajor"] == 2
             and type(value["applicationMajor"]) is int and value["applicationMajor"] == 2
             and value["purpose"] == "workspace")
    for key in ("accountId", "hostId", "hostAuthorizationId", "consumerAuthorizationId", "consumerId", "grantId", "workspaceId", "workspaceEpoch", "runtimeId"):
        _bytes(value[key], 16, 16)
    for key in ("hostFingerprint", "consumerFingerprint", "nonce"):
        _bytes(value[key], 32, 32)
    for key in ("accessEpoch", "grantRevision", "runtimeGeneration", "expiresAt"):
        _decimal(value[key])
    _text(value["accountSessionId"], 128)
    caps = value["capabilities"]
    _require(type(caps) is list and len(caps) <= 64)
    for cap in caps:
        _text(cap, 128)  # Canonical registry/dependency checks remain in Rust.


def _context(value):
    _object(value, "version grant channelId initiatorRole responderRole purpose terminal issuedAt expiresAt")
    _require(type(value["version"]) is int and value["version"] == 3
             and value["initiatorRole"] == "device" and value["responderRole"] == "host"
             and value["purpose"] in ("workspace", "terminal"))
    _grant(value["grant"])
    _bytes(value["channelId"], 16, 16)
    _terminal(value["terminal"])
    _decimal(value["issuedAt"])
    _decimal(value["expiresAt"])


def _authority(value):
    _object(value, "hostAuthorizationId consumerAuthorizationId accountSessionId accessEpoch grantRevision workspaceEpoch runtimeId runtimeGeneration terminalMembership")
    for key in ("hostAuthorizationId", "consumerAuthorizationId", "workspaceEpoch", "runtimeId"):
        _bytes(value[key], 16, 16)
    for key in ("accessEpoch", "grantRevision", "runtimeGeneration"):
        _decimal(value[key])
    _text(value["accountSessionId"], 128)
    _terminal(value["terminalMembership"])


def _command(value):
    _require(type(value) is dict and type(value.get("op")) is str)
    op = value["op"]
    fields = {
        "init": "account_id host_id window_id", "sign_enrollment": "canonical_cbor",
        "sign_window": "canonical_cbor", "sign_grant": "grant", "sign_context": "context",
        "start": "slot initiator expected_context_cbor stored_signed_grant_wire admission_wire host_identity_wire consumer_identity_wire host_pin consumer_pin current_authority",
        "read": "slot bytes", "write": "slot", "finish": "slot", "seal": "slot bytes",
        "open": "slot bytes", "dispose": "slot", "shutdown": "",
    }
    _require(op in fields)
    _object(value, "op " + fields[op])
    if "slot" in value:
        _text(value["slot"], 64)
    if op == "init":
        for key in ("account_id", "host_id", "window_id"):
            _bytes(value[key], 16, 16)
            _require(any(value[key]))
    elif op in ("sign_enrollment", "sign_window"):
        _bytes(value["canonical_cbor"], 1024)
    elif op == "sign_grant":
        _grant(value["grant"])
    elif op == "sign_context":
        _context(value["context"])
    elif op == "start":
        _require(type(value["initiator"]) is bool)
        _bytes(value["expected_context_cbor"], 32 * 1024)
        for key in ("stored_signed_grant_wire", "admission_wire", "host_identity_wire", "consumer_identity_wire"):
            _wire(value[key])
        _bytes(value["host_pin"], 32, 32)
        _bytes(value["consumer_pin"], 32, 32)
        _authority(value["current_authority"])
    elif op in ("read", "seal", "open"):
        _bytes(value["bytes"], {"read": 512, "seal": 16384, "open": 16512}[op])
    return op


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _parse(line):
    _require(len(line) <= _MAX_LINE and line.endswith(b"\n"))
    try:
        return json.loads(line, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(BridgeRejected()))
    except (ValueError, RecursionError, UnicodeError):
        raise BridgeRejected() from None


def _response(value, op):
    _require(type(value) is dict and type(value.get("ok")) is bool)
    if not value["ok"]:
        _require(value == {"ok": False, "error": "NATIVE_FIXTURE_REJECTED"})
        return
    _object(value, "ok result")
    result = value["result"]
    if op in ("write", "seal", "open"):
        _bytes(result, {"write": 512, "seal": 16512, "open": 16384}[op])
    elif op in ("sign_enrollment", "sign_window", "sign_grant", "sign_context"):
        _wire(result)
    elif op == "init":
        _object(result, "initiation hostIdentityWire consumerIdentityWire hostPin consumerPin hostBundle consumerBundle")
        _object(result["initiation"], "keyCommitment proof")
        _require(type(result["initiation"]["keyCommitment"]) is str
                 and re.fullmatch(r"[0-9a-f]{64}", result["initiation"]["keyCommitment"]))
        for wire in (result["initiation"]["proof"], result["hostIdentityWire"], result["consumerIdentityWire"]):
            _wire(wire)
        for key in ("hostPin", "consumerPin"):
            _bytes(result[key], 32, 32)
        for key in ("hostBundle", "consumerBundle"):
            signed = result[key]
            _object(signed, "bundle signature")
            _bytes(signed["signature"], 64, 64)
            bundle = signed["bundle"]
            _object(bundle, "version account_id subject_id role key_version identity_key channel_key mailbox_key")
            _require(type(bundle["version"]) is int and bundle["version"] == 1
                     and type(bundle["key_version"]) is int and 0 < bundle["key_version"] < 2**32
                     and bundle["role"] in ("host", "device"))
            for name in ("account_id", "subject_id"):
                _bytes(bundle[name], 16, 16)
            for name in ("identity_key", "channel_key", "mailbox_key"):
                _bytes(bundle[name], 32, 32)
    else:
        _require(type(result) is list and not result)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode))


class NativeBridge:
    """Own a retained native direct child and exactly one private socket client."""
    def __init__(self, *, binary_path, expected_sha256, fixture_path):
        self.socket_path = None
        self._child = None
        self._thread = None
        self._listener = None
        self._client = None
        self._dir_fd = None
        self._wake = None
        self._stop = threading.Event()
        self._failed = threading.Event()
        self._closed = threading.Event()
        self.cleanup_complete = False
        self.command_count = 0
        self.stderr_byte_count = 0
        self._socket_identity = None
        self._shutdown = False
        self._stderr_closed = False
        try:
            _require(threading.current_thread() is threading.main_thread())
            owned.require_process_ownership()
            _require(type(expected_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", expected_sha256))
            binary = Path(binary_path)
            _require(binary.is_absolute() and not binary.is_symlink())
            binary = binary.resolve(strict=True)
            info = binary.stat()
            _require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 and not info.st_mode & 0o022)
            _require(_sha256(binary) == expected_sha256)
            binary_identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            directory = Path(fixture_path)
            _require(directory.is_absolute() and not directory.is_symlink())
            directory = directory.resolve(strict=True)
            info = directory.lstat()
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
            self._directory = directory
            self._dir_identity = _identity(info)
            self._dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            _require(_identity(os.fstat(self._dir_fd)) == self._dir_identity)
            name = "s-" + uuid.uuid4().hex + ".sock"
            self.socket_path = directory / name
            _require(len(os.fsencode(self.socket_path)) <= 103)
            self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._listener.bind(str(self.socket_path))
            original = self.socket_path.lstat()
            _require(stat.S_ISSOCK(original.st_mode) and original.st_uid == os.getuid())
            os.chmod(self.socket_path, 0o600, follow_symlinks=False)
            current = self.socket_path.lstat()
            _require((current.st_dev, current.st_ino) == (original.st_dev, original.st_ino))
            _require(stat.S_ISSOCK(current.st_mode) and current.st_uid == os.getuid()
                     and stat.S_IMODE(current.st_mode) == 0o600)
            self._socket_identity = _identity(current)
            _require(self._directory_matches())
            self._listener.listen(1)
            self._listener.setblocking(False)
            home = directory / ("native-home-" + uuid.uuid4().hex)
            os.mkdir(home.name, mode=0o700, dir_fd=self._dir_fd)
            _require(self._directory_matches())
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            self._child = subprocess.Popen(
                [str(binary)], cwd=home,
                env={"HOME": str(home), "TMPDIR": str(home), "PATH": "/usr/bin:/bin", "LANG": "C"},
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                bufsize=0, start_new_session=False,
            )
            after = binary.stat()
            _require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == binary_identity
                     and _sha256(binary) == expected_sha256)
            _require(self._directory_matches())
            for stream in (self._child.stdin, self._child.stdout, self._child.stderr):
                os.set_blocking(stream.fileno(), False)
            self._wake = socket.socketpair()
            for item in self._wake:
                item.setblocking(False)
            self._thread = threading.Thread(target=self._serve, name="native-fixture-bridge", daemon=True)
            self._thread.start()
        except BaseException:
            self._failed.set()
            self._cleanup()
            raise BridgeRejected() from None

    @property
    def failed(self):
        return self._failed.is_set()

    @property
    def closed(self):
        return self._closed.is_set()

    def _directory_matches(self):
        return (self._dir_fd is not None
                and _identity(os.fstat(self._dir_fd)) == self._dir_identity
                and _identity(self._directory.lstat()) == self._dir_identity)

    def _wait(self, source, writing, deadline, *, terminal=False):
        while True:
            _require(not self._stop.is_set() and time.monotonic() < deadline)
            read = [self._wake[0]]
            if not self._stderr_closed:
                read.append(self._child.stderr)
            if source is not self._child.stdout and not terminal:
                read.append(self._child.stdout)
            if self._client is not None and (source is not self._client or writing):
                read.append(self._client)
            if not writing:
                read.append(source)
            ready, writable, exceptional = select.select(read, [source] if writing else [], read, min(_TICK, max(0, deadline-time.monotonic())))
            _require(not exceptional and self._wake[0] not in ready)
            if self._child.stderr in ready:
                data = os.read(self._child.stderr.fileno(), 4096)
                self.stderr_byte_count += len(data)
                # Canonical native fixture is silent. Never retain its bytes.
                _require(not data and self._shutdown)
                self._stderr_closed = True  # Only explicit shutdown may exit after its response.
            if self._client is not None and self._client in ready and (source is not self._client or writing):
                # No queued commands, replay queue, or ignored disconnects.
                raise BridgeRejected()
            if self._child.stdout in ready and source is not self._child.stdout:
                raise BridgeRejected()  # Unsolicited output or helper EOF.
            if source in (writable if writing else ready):
                return

    def _line(self, source, deadline, *, request=False):
        data = bytearray()
        first = True
        while True:
            self._wait(source, False, deadline)
            try:
                piece = source.recv(min(4096, _MAX_LINE+1-len(data))) if isinstance(source, socket.socket) else os.read(source.fileno(), min(4096, _MAX_LINE+1-len(data)))
            except BlockingIOError:
                continue
            _require(piece)
            if request and first:
                deadline = min(deadline, time.monotonic()+_IO_TIMEOUT)
            first = False
            data.extend(piece)
            _require(len(data) <= _MAX_LINE)
            if b"\n" in piece:
                _require(data.endswith(b"\n") and data.count(b"\n") == 1)
                return bytes(data), deadline

    def _write(self, target, data, deadline, *, terminal=False):
        view = memoryview(data)
        while view:
            self._wait(target, True, deadline, terminal=terminal)
            try:
                count = target.send(view) if isinstance(target, socket.socket) else os.write(target.fileno(), view)
            except BlockingIOError:
                continue
            _require(count > 0)
            view = view[count:]

    def _serve(self):
        try:
            deadline = time.monotonic()+_CONNECT_TIMEOUT
            self._wait(self._listener, False, deadline)
            self._client, _ = self._listener.accept()
            self._client.setblocking(False)
            self._listener.close()
            self._listener = None
            while not self._stop.is_set():
                if self.command_count >= _MAX_COMMANDS:
                    self._failed.set()
                    break  # Do not append an unsolicited error after the last response.
                line, deadline = self._line(self._client, time.monotonic()+_IDLE_TIMEOUT, request=True)
                command = _parse(line)
                op = _command(command)
                self._shutdown = op == "shutdown"
                self.command_count += 1
                self._write(self._child.stdin, line, deadline)
                reply, _ = self._line(self._child.stdout, deadline)
                _response(_parse(reply), op)
                self._write(self._client, reply, deadline, terminal=op == "shutdown")
                del line, command, reply  # No completed traffic remains queued in Python.
                if op == "shutdown":
                    break
        except BaseException:
            if not self._stop.is_set():
                self._failed.set()
                if self._client is not None:
                    try:
                        self._client.send(_ERROR)
                    except OSError:
                        pass
        finally:
            self._cleanup()

    def _cleanup(self):
        # Only the worker runs cleanup after start. Constructor failures occur
        # before a worker is running; close() merely wakes and joins that worker.
        safe = True
        if self._child is not None:
            try:
                owned.require_unreaped_child(self._child)
                try:
                    os.kill(self._child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                time.sleep(0.1)
                owned.require_unreaped_child(self._child)
                try:
                    os.kill(self._child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                # Discard pipe buffers, without communicate() allocations or
                # private diagnostics. Closing pipes also bounds stderr drain.
                for stream in (self._child.stdin, self._child.stdout, self._child.stderr):
                    stream.close()
                self._child.wait(timeout=1)  # The one final reap, never earlier.
            except BaseException:
                safe = False
                self._failed.set()
            finally:
                for stream in (self._child.stdin, self._child.stdout, self._child.stderr):
                    stream.close()
        for item in (self._client, self._listener, *(self._wake or ())):
            if item is not None:
                item.close()
        if self._socket_identity is not None:
            try:
                if not safe or not self._directory_matches():
                    safe = False
                elif _identity(self.socket_path.lstat()) != self._socket_identity:
                    safe = False
                else:
                    os.unlink(self.socket_path.name, dir_fd=self._dir_fd)
            except OSError:
                safe = False
        if self._dir_fd is not None:
            os.close(self._dir_fd)
            self._dir_fd = None
        self.cleanup_complete = safe
        if not safe:
            self._failed.set()
        self._closed.set()

    def close(self):
        self._stop.set()
        if self._wake is not None and not self.closed:
            try:
                self._wake[1].send(b"x")
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
        _require(self.closed and self.cleanup_complete)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
