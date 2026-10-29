#!/usr/bin/env python3
"""Actual product CLI/PTY responsiveness during an HTTPS handshake stall.

Development evidence only: exercises ProtectedFile and the default HTTP worker,
local consent fencing and pending-login cancellation. No successful account login,
cloud revoke, reenrollment, custom trust roots, or injected auth implementation.
Never retains CLI/PTY output, private profiles, SQLite, or secret bundle bytes.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import socket
import sqlite3
import stat
import struct
import subprocess
import tarfile
import tempfile
import termios
import threading
import time
import uuid

from owned_process import (initialize_process_ownership, require_unreaped_child,
                           run_owned, stop_group)

ROOT = Path(__file__).resolve().parents[1]


PRODUCT_CRATES = ("lomiremote", "lomi-host", "lomi-host-store", "lomi-host-auth",
                  "lomi-host-http", "lomi-platform", "lomi-terminal",
                  "lomi-remote-protocol", "lomi-remote-crypto", "lomi-terminal-state",
                  "lomi-windows-pty")
VENDORS = ("crates/lomi-remote-crypto/vendor/snow", "vendor/vte", "vendor/alacritty_terminal")
SOURCE_ROOTS = tuple("crates/" + name for name in PRODUCT_CRATES) + VENDORS
CODE_SUFFIXES = {".rs", ".c", ".m", ".h"}
FIXED_SOURCES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "README.md",
                 "tools/validate_host_login_process.py", "tools/owned_process.py")


def environment_name(name):
    lowered = name.lower()
    return (lowered.startswith(".env") or lowered.startswith("env.")
            or lowered.endswith(".env") or ".env." in lowered)


def checked_public_file(repo, relative):
    """Check every path component before opening any selected source bytes."""
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts or any(environment_name(p) for p in relative.parts):
        raise ValueError("non_public_source_path")
    current = repo
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("source_symlink")
    if not stat.S_ISREG(current.lstat().st_mode):
        raise ValueError("source_not_regular")
    return current


def source_inventory(repo, roots=SOURCE_ROOTS, fixed=FIXED_SOURCES):
    """Typed public code selection, deliberately not a repository-wide scan.

    This guards live originals and records their exact selected bytes; it is
    not a hermetic build closure. Non-code test fixtures are not collected.
    """
    selected = set(fixed)
    for name in roots:
        base = repo / name
        if base.is_symlink() or not base.is_dir():
            raise ValueError("invalid_source_root")
        for filename in ("Cargo.toml", "build.rs", "LICENSE", "LICENSE-MIT", "LICENSE-APACHE"):
            candidate = base / filename
            if candidate.exists() or candidate.is_symlink():
                selected.add(str(candidate.relative_to(repo)))
        for surface in ("src", "tests"):
            tree = base / surface
            if tree.is_symlink():
                raise ValueError("source_symlink")
            if not tree.exists():
                continue
            def failed(error):
                raise error
            for directory, directories, files in os.walk(tree, followlinks=False, onerror=failed):
                # Privacy rejection happens before traversal or opening files.
                directories[:] = sorted(d for d in directories if not environment_name(d))
                for child in directories:
                    if (Path(directory) / child).is_symlink():
                        raise ValueError("source_symlink")
                for filename in sorted(files):
                    if environment_name(filename):
                        continue
                    candidate = Path(directory) / filename
                    if candidate.suffix in CODE_SUFFIXES:
                        selected.add(str(candidate.relative_to(repo)))
    files = {}
    for name in sorted(selected):
        source = checked_public_file(repo, name)
        files[name] = hashlib.sha256(source.read_bytes()).hexdigest()
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"algorithm": "sha256", "digest": hashlib.sha256(encoded).hexdigest(),
            "files": files, "scope": "typed product code and Cargo inputs; guarded live originals, nonhermetic"}


def visible_terminal_bytes(data):
    """Normalize a bounded synthetic render buffer; never retain its contents."""
    # Complete OSC strings end with BEL or ST; hide incomplete OSC payloads.
    data = re.sub(rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", b"", data)
    data = re.sub(rb"\x1b\].*$", b"", data, flags=re.S)
    data = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data)
    data = re.sub(rb"\x1b\[[0-?]*[ -/]*$", b"", data)
    return re.sub(rb"\x1b[@-_]", b"", data)


def source_privacy_self_test():
    with tempfile.TemporaryDirectory(prefix="lomi-public-source-test-") as directory:
        root = Path(directory).resolve()
        source = root / "crate/src"
        source.mkdir(parents=True)
        (source / "lib.rs").write_text("pub fn public() {}")
        names = (".env", ".env.rs", "env.local", "local-db.env", "local-db.env.rs")
        for name in names:
            (source / name).write_text("synthetic-private-sentinel")
        (source / "env.local.d").mkdir()
        (source / "env.local.d/hidden.rs").write_text("synthetic-private-sentinel")
        inventory = source_inventory(root, roots=("crate",), fixed=())
        assert set(inventory["files"]) == {"crate/src/lib.rs"}
        for name in names:
            try:
                checked_public_file(root, "crate/src/" + name)
            except ValueError:
                pass
            else:
                raise AssertionError("env_name_not_rejected")
        try:
            checked_public_file(root, "crate/src/env.local.d/hidden.rs")
        except ValueError:
            pass
        else:
            raise AssertionError("env_ancestor_not_rejected")
        (source / "linked.rs").symlink_to(source / "lib.rs")
        try:
            source_inventory(root, roots=("crate",), fixed=())
        except ValueError:
            pass
        else:
            raise AssertionError("source_symlink_not_rejected")
    print("typed source privacy sentinels: passed")
    # A transaction context does not close a Connection; a retained WAL reader
    # prevents a new EXCLUSIVE owner even after its SELECT finishes.
    with tempfile.TemporaryDirectory(prefix="lomi-sqlite-close-test-") as directory:
        database = Path(directory) / "synthetic.sqlite3"
        with closing(sqlite3.connect(database, timeout=0.05)) as setup:
            setup.execute("PRAGMA journal_mode=WAL")
            setup.execute("CREATE TABLE public_state(value INTEGER)")
            setup.execute("INSERT INTO public_state VALUES(1)")
            setup.commit()
        with closing(sqlite3.connect(database, timeout=0.05)) as reader:
            with reader:
                assert reader.execute("SELECT value FROM public_state").fetchone() == (1,)
            with closing(sqlite3.connect(database, timeout=0.05)) as owner:
                owner.execute("PRAGMA locking_mode=EXCLUSIVE")
                try:
                    owner.execute("BEGIN EXCLUSIVE")
                except sqlite3.OperationalError as error:
                    assert error.sqlite_errorcode == sqlite3.SQLITE_BUSY
                else:
                    raise AssertionError("retained_reader_should_block_owner")
        with closing(sqlite3.connect(database, timeout=0.05)) as owner:
            owner.execute("PRAGMA locking_mode=EXCLUSIVE")
            owner.execute("BEGIN EXCLUSIVE")
            assert owner.execute("SELECT value FROM public_state").fetchone() == (1,)
    print("explicit SQLite reader close releases exclusive owner: passed")
    chunks = (b"\x1b[?1049hControl: in\x1b[", b"32mput and\x1b]0;hidden",
              b" synthetic marker\x1b", b"\\ resize\x1b[0m")
    data = bytearray()
    for chunk in chunks:
        data.extend(chunk)
        assert b"hidden" not in visible_terminal_bytes(bytes(data))
    assert visible_terminal_bytes(bytes(data)) == b"Control: input and resize"
    assert visible_terminal_bytes(b"before\x1b]0;hidden\x07after") == b"beforeafter"
    assert visible_terminal_bytes(b"marker\x1b[12;") == b"marker"
    print("split CSI/OSC in-memory normalization: passed")


class HandshakeStall:
    """Accept TCP, retaining no received bytes and sending no TLS bytes."""
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.accepted = threading.Event()
        self.stopping = threading.Event()
        self.connections = []
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.connections.append(connection)
            self.accepted.set()

    def close(self):
        self.stopping.set()
        self.listener.close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("stall_thread_cleanup")
        for connection in self.connections:
            connection.close()


def public_database(profile):
    """Select only schema and known public fields; never return database text."""
    with closing(sqlite3.connect(f"file:{profile / 'host.sqlite3'}?mode=ro", uri=True,
                                 timeout=1)) as db:
        tables = [r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        forbidden = ("private_key", "privatekey", "access_token", "accesstoken",
                     "refresh_token", "refreshtoken", "device_code", "devicecode",
                     "bootstrapcredential", "pkce_verifier", "pkceverifier")
        credential_fields = ('"seed"', '"credentials"', '"access"', '"refresh"',
                             '"device"', '"bootstrap"', '"usercode"',
                             "-----begin private key", "-----begin openssh private key")
        schema_clean = True
        for table in tables:
            # Names come solely from SQLite's schema; safely quote identifiers.
            quoted = '"' + table.replace('"', '""') + '"'
            columns = list(db.execute(f"PRAGMA table_info({quoted})"))
            schema_clean &= not any(needle in c[1].lower() for c in columns
                                    for needle in forbidden)
            # Inspect text in memory for static credential field names only.
            # Neither row values nor matches leave this function.
            for row in db.execute(f"SELECT * FROM {quoted}"):
                for value in row:
                    if isinstance(value, str):
                        schema_clean &= not any(n in value.lower() for n in forbidden + credential_fields)
                        schema_clean &= re.search(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", value) is None
        generation, locked, pending = db.execute(
            "SELECT generation,locked,pending_cloud_revoke FROM authorization_state WHERE id=1").fetchone()
        projects = {workspace: {"consent": bool(consent), "fence": int(fence)}
                    for workspace, consent, fence in db.execute(
                        "SELECT workspace,consent,fence FROM projects WHERE removed=0")}
        outbox = {workspace: json.loads(publication)["enabled"]
                  for workspace, publication in db.execute("SELECT workspace,publication FROM outbox")}
        intent_absent = db.execute(
            "SELECT count(*) FROM metadata WHERE key='login_generation'").fetchone()[0] == 0
        return {"generation": int(generation), "locked": bool(locked),
                "pending": bool(pending), "projects": projects, "outbox": outbox,
                "intentAbsent": intent_absent, "schemaClean": schema_clean}


def main():
    initialize_process_ownership()  # Before any thread or child, including builds.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="Synthetic source privacy sentinels only")
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/lomiremote")
    parser.add_argument("--build", action="store_true", help="Build the default product offline in root target")
    parser.add_argument("--build-proof-report", type=Path, help="Prior public process receipt proving the supplied default binary build")
    args = parser.parse_args()
    if args.self_test:
        source_privacy_self_test()
        return 0
    if not args.run:
        print("Not run: pass --run after freezing product sources.")
        return 0
    os.umask(0o077)
    run_id = str(uuid.uuid4())
    artifact = ROOT / "artifacts/host-login-process" / run_id
    artifact.mkdir(parents=True, mode=0o700)
    report = {"runId": run_id, "kind": "actual-product-host-login-stall",
              "startedAt": datetime.now(timezone.utc).isoformat(), "passed": False,
              "scope": "Default product worker and ProtectedFile; stalled HTTPS initiation, local CLI/PTY responsiveness, offline consent fences and pending-login cancellation. No successful login, cloud revoke or reenrollment proof.",
              "operations": [], "checks": {}, "cleanup": {}}
    report_path = artifact / "report.json"
    report_lock = threading.Lock()

    def persist():
        with report_lock:
            temporary = report_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            temporary.replace(report_path)

    def check(name, condition):
        report["checks"][name] = bool(condition)
        persist()
        if not condition:
            raise RuntimeError(name)

    def operation(label, argv, *, environment, timeout=3, decode=False):
        safe = [str(a).replace(str(private), "<private>") if private else str(a) for a in argv]
        entry = {"name": label, "command": safe, "complete": False}
        report["operations"].append(entry)
        start = time.monotonic()
        try:
            result = run_owned([str(a) for a in argv], cwd=ROOT, env=environment, timeout=timeout)
            entry.update(complete=True, exitCode=result.returncode)
            if result.returncode:
                raise RuntimeError("cli_exit")
            return json.loads(result.stdout) if decode else None
        finally:
            entry["durationSeconds"] = round(time.monotonic() - start, 4)
            persist()

    private = None
    host = None
    host_operation = None
    stall = None
    stopped = False
    attach_cleanup_known = True
    workload_cleanup_known = True
    persist()
    try:
        before = source_inventory(ROOT)
        report["sourceBefore"] = before
        # Exact selected public sources; no profile/env/build data is eligible.
        with tarfile.open(artifact / "source.tar.gz", "w:gz") as archive:
            copied = {}
            for name, expected in before["files"].items():
                data = checked_public_file(ROOT, name).read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                if digest != expected:
                    raise RuntimeError("source_changed_during_copy")
                entry = tarfile.TarInfo(name)
                entry.mode = 0o644
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
                copied[name] = digest
        report["sourceCopied"] = {"files": copied, "digest": before["digest"]}
        report["sourceArchiveSha256"] = hashlib.sha256((artifact / "source.tar.gz").read_bytes()).hexdigest()
        private = Path(tempfile.mkdtemp(prefix="lomi-login-", dir=Path("/tmp").resolve(strict=True))).resolve(strict=True)
        home = private / "home"
        profile = private / "profile"
        check("socketPathWithinProductLimit", len(os.fsencode(profile / "host.sock")) <= 100)
        home.mkdir(mode=0o700)
        environment = {"HOME": str(home), "PATH": "/usr/bin:/bin", "SHELL": "/bin/sh",
                       "TERM": "xterm-256color", "LANG": "C", "TMPDIR": str(private)}
        check("verifiedSystemShell", Path("/bin/sh").resolve(strict=True).is_file())
        binary = args.binary.resolve(strict=True) if not args.build else args.binary.absolute()
        if args.build:
            cargo = Path.home() / ".cargo/bin/cargo"
            build_env = {**environment, "PATH": str(cargo.parent) + ":/usr/bin:/bin",
                         "CARGO_HOME": str(Path.home() / ".cargo"),
                         "RUSTUP_HOME": str(Path.home() / ".rustup"),
                         "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2",
                         "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                         "CARGO_PROFILE_RELEASE_DEBUG": "0", "CARGO_TARGET_DIR": str(ROOT / "target")}
            operation("build-default-product", [cargo, "build", "--offline", "--locked", "-p", "lomiremote"],
                      environment=build_env, timeout=900)
            binary = (ROOT / "target/debug/lomiremote").resolve(strict=True)
        report["binary"] = {"sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                            "buildInThisRun": args.build,
                            "provenance": "root default build" if args.build else "supplied binary; correlate hash with external root build evidence"}

        if args.build_proof_report is not None:
            proof_path = args.build_proof_report.resolve(strict=True)
            if not proof_path.is_relative_to(ROOT / "artifacts/host-login-process") or proof_path.name != "report.json":
                raise ValueError("invalid_public_build_receipt")
            proof = json.loads(proof_path.read_text())
            check("externalBuildBinaryHashMatches", proof["binary"]["sha256"] == report["binary"]["sha256"])
            check("externalDefaultBuildSucceeded", proof["binary"]["buildInThisRun"] and any(
                op["name"] == "build-default-product" and op.get("complete") and op.get("exitCode") == 0
                for op in proof["operations"]))
            current_sources = {name: digest for name, digest in before["files"].items()
                               if name != "tools/validate_host_login_process.py"}
            built_sources = {name: digest for name, digest in proof["sourceBefore"]["files"].items()
                             if name != "tools/validate_host_login_process.py"}
            check("externalBuildOtherSelectedSourcesMatch", current_sources == built_sources)
            report["binary"]["provenance"] = "reused default product binary; matching prior root offline build and unchanged selected compiled sources"
            report["binary"]["externalBuildReceipt"] = str(proof_path.relative_to(ROOT))

        def call(label, *arguments, decode=False, timeout=3):
            return operation(label, [binary, "--profile-dir", profile, *arguments],
                             environment=environment, timeout=timeout, decode=decode)

        def value(label, *arguments):
            return call(label, *arguments, decode=True)["result"]["Ok"]["value"]

        def start_host():
            nonlocal host, host_operation
            host_operation = {"name": "foreground-host", "command": [str(binary), "--profile-dir", "<private>/profile", "daemon", "run"], "complete": False}
            report["operations"].append(host_operation)
            host_operation["startedMonotonic"] = time.monotonic()
            host = subprocess.Popen([str(binary), "--profile-dir", str(profile), "daemon", "run"],
                                    cwd=private, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    start_new_session=True)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                require_unreaped_child(host)
                if (profile / "discovery.json").exists():
                    return value("host-ready", "status", "--json")
                time.sleep(0.03)
            raise TimeoutError("host_start")

        initial = start_host()
        for index in range(2):
            project = private / ("project-" + str(index))
            project.mkdir(mode=0o700)
            call("workspace-add-" + str(index), "workspace", "add", "--name", "Synthetic " + str(index), "--path", str(project))
        workspaces = value("workspace-list", "workspace", "list", "--json")
        ids = [w["workspaceId"] for w in workspaces]
        check("twoWorkspaces", len(ids) == 2)
        for index, workspace in enumerate(ids):
            call("share-" + str(index), "workspace", "share", workspace, "--confirm")
        call("stop-baseline-host", "daemon", "stop", "--confirm", timeout=20)
        check("baselineHostActualExit", host.wait(timeout=20) == 0)
        host_operation.update(complete=True, exitCode=host.returncode, durationSeconds=round(time.monotonic() - host_operation.pop("startedMonotonic"), 4))
        host = None
        shared = public_database(profile)
        check("explicitLocalConsent", all(p["consent"] for p in shared["projects"].values()))
        initial = start_host()  # This runtime owns the actual stalled-worker proof.
        workload_cleanup_known = False
        call("terminal-create", "terminal", "create", "--workspace", ids[0], "--json", decode=True)
        pane = call("terminal-descriptors", "terminal", "list", "--workspace", ids[0], "--json", decode=True)["state"]["tabs"][0]["layout"]["pane"]
        stall = HandshakeStall()
        call("configure-protected-file", "auth", "configure", "--origin", f"https://localhost:{stall.port}",
             "--client-id", "lomi-remote-host", "--provider", "protected-file", "--ack-os-permissions-only", "--confirm", "--json", decode=True)
        accepted = value("login-start", "login", "--json")
        check("durableLoginAccepted", isinstance(accepted.get("operationId"), str))
        check("realHttpsConnectionAccepted", stall.accepted.wait(4))
        check("hostAliveAfterLoginCliExit", os.waitid(os.P_PID, host.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None)
        bundle = profile / "host-secrets.bundle"
        check("protectedFilePrivate", bundle.is_file() and not bundle.is_symlink()
              and stat.S_IMODE(bundle.stat().st_mode) == 0o600 and bundle.stat().st_uid == os.getuid())
        login_state = value("login-status-stalled", "login", "status", "--json")
        check("workerStalledInitializing", login_state["phase"] == "initializing" and login_state["network"] == "working" and login_state["storage"] == "available")
        # Two independent real CLI processes overlap while transport is blocked.
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(value, "parallel-status-" + str(i), "status", "--json") for i in range(2)]
            statuses = [future.result(timeout=4) for future in futures]
        check("twoCliSameLiveRuntime", all(s["runtimeId"] == initial["runtimeId"] for s in statuses))

        master, slave = pty.openpty()
        attached = None
        workload_cleanup_known = False  # Host now owns an independently sessioned PTY.
        attach_operation = {"name": "pty-attach-control", "command": [str(binary), "--profile-dir", "<private>/profile", "terminal", "attach", "--workspace", ids[0], "--pane", pane["paneId"], "--control"], "complete": False}
        report["operations"].append(attach_operation)
        attach_start = time.monotonic()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
            previous = termios.tcgetattr(slave)
            attach_cleanup_known = False
            attached = subprocess.Popen([str(binary), "--profile-dir", str(profile), "terminal", "attach",
                                        "--workspace", ids[0], "--pane", pane["paneId"], "--control"],
                                       cwd=private, env=environment, stdin=slave, stdout=slave, stderr=slave,
                                       start_new_session=True)
            diagnostics = {"bytesObserved": False, "altScreenSeen": False,
                           "initialObserverSeen": False, "cursorQuerySeen": False}
            report["ptyDiagnostics"] = diagnostics
            def observe(marker, timeout=2):
                end = time.monotonic() + timeout
                tail = bytearray()
                while time.monotonic() < end:
                    if select.select([master], [], [], 0.03)[0]:
                        tail.extend(os.read(master, 65536))
                        diagnostics["bytesObserved"] |= bool(tail)
                        diagnostics["altScreenSeen"] |= b"\x1b[?1049h" in tail
                        diagnostics["cursorQuerySeen"] |= b"\x1b[6n" in tail or b"\x1b[?6n" in tail
                        visible = visible_terminal_bytes(bytes(tail))
                        diagnostics["initialObserverSeen"] |= b"Observer" in visible
                        if marker in (tail if marker.startswith(b"\x1b") else visible):
                            return True
                        del tail[:-131072]
                return False
            check("ptyControlDuringStall", observe(b"input and", timeout=5))
            # Rendered output is compared only in memory, never logged or hashed.
            os.write(master, b"printf '%s%s\\n' 'LMSTALL_' 'OK'\r")
            check("ptySyntheticOutputDuringStall", observe(b"LMSTALL_OK"))
            check("workerStillBlockedBeforeFences", value("before-fence-login-status", "login", "status", "--json")["network"] == "working")
            call("unshare-offline", "workspace", "unshare", ids[0], "--confirm")
            unshared = value("workspaces-after-unshare", "workspace", "list", "--json")
            sharing = {w["workspaceId"]: w["sharing"] for w in unshared}
            check("unshareImmediateConsentFence", sharing[ids[0]] == "disabled" and sharing[ids[1]] == "enabled")
            logged_out = value("logout-offline", "logout", "--confirm", "--json")
            after_logout = value("workspaces-after-logout", "workspace", "list", "--json")
            check("logoutImmediateGlobalFence", int(logged_out["generation"]) > shared["generation"]
                  and logged_out["locked"] and logged_out["operationId"] is None
                  and all(w["sharing"] == "disabled" for w in after_logout))
            check("logoutPendingWhileNetworkBlocked", logged_out["pendingCloudRevoke"])
            check("cliResponsiveAfterFence", value("status-after-fence", "status", "--json")["runtimeId"] == initial["runtimeId"])
            surviving = call("terminal-descriptors-after-fence", "terminal", "list", "--workspace", ids[0], "--json", decode=True)["state"]["tabs"][0]["layout"]["pane"]
            check("samePtySessionAfterFence", surviving["session"] == pane["session"])
            report["publicFence"] = {"beforeGeneration": shared["generation"], "afterGeneration": int(logged_out["generation"]),
                                     "workspaces": ids, "runtimeId": initial["runtimeId"]}
            os.write(master, b"printf '%s%s\\n' 'LMAFTER_' 'OK'\r")
            check("ptyResponsiveAfterFence", observe(b"LMAFTER_OK"))
            os.write(master, b"\x1d")
            check("viewExitRestoresScreen", observe(b"\x1b[?1049l"))
            check("viewExitConfirmed", attached.wait(timeout=2) == 0)
            attach_cleanup_known = True
            attach_operation.update(complete=True, exitCode=attached.returncode, durationSeconds=round(time.monotonic() - attach_start, 4))
            check("viewRestoresTerminalModes", termios.tcgetattr(slave) == previous)
        finally:
            if attached is not None and attached.returncode is None:
                try:
                    stop_group(attached)
                    attach_cleanup_known = attached.returncode is not None
                    attach_operation.update(complete=True, exitCode=attached.returncode, durationSeconds=round(time.monotonic() - attach_start, 4))
                except BaseException as error:
                    report["cleanup"]["attachErrorClass"] = type(error).__name__
            elif attached is not None:
                attach_cleanup_known = True
            os.close(master)
            os.close(slave)
        report["network"] = {"acceptedConnections": len(stall.connections), "receivedBytesRetained": False, "sentTlsBytes": False}
        stall.close()
        stall = None
        # Stop joins the real worker; subsequent start proves the durable fence.
        call("stop-host", "daemon", "stop", "--confirm", timeout=20)
        check("firstHostActualExit", host.wait(timeout=20) == 0)
        host_operation.update(complete=True, exitCode=host.returncode, durationSeconds=round(time.monotonic() - host_operation.pop("startedMonotonic"), 4))
        host = None
        workload_cleanup_known = True
        # The exclusive SQLite owner lock is respected: inspect committed public
        # rows only after actual owner exit, before the next actual owner starts.
        fenced = public_database(profile)
        check("offlineFencesDurableInSqlite", fenced["generation"] == int(logged_out["generation"])
              and fenced["generation"] > shared["generation"] and fenced["locked"]
              and fenced["intentAbsent"] and all(not p["consent"] for p in fenced["projects"].values())
              and all(fenced["outbox"].get(w) is False for w in ids)
              and fenced["projects"][ids[0]]["fence"] == shared["projects"][ids[0]]["fence"] + 2
              and fenced["projects"][ids[1]]["fence"] == shared["projects"][ids[1]]["fence"] + 1)
        check("sqliteHasNoCredentialFields", shared["schemaClean"] and fenced["schemaClean"])
        fresh = start_host()
        check("freshActualProcessRuntime", fresh["runtimeId"] != initial["runtimeId"])
        check("consentDisabledAfterRestart", all(w["sharing"] == "disabled" for w in value("workspaces-after-restart", "workspace", "list", "--json")))
        deadline = time.monotonic() + 3
        while True:
            restart_login = value("login-status-after-restart", "login", "status", "--json")
            if not restart_login["pendingCloudRevoke"] or time.monotonic() >= deadline:
                break
            time.sleep(0.1)
        check("restartDoesNotResumeLogin", restart_login["operationId"] is None)
        check("pendingLoginCancellationCompletes", not restart_login["pendingCloudRevoke"])
        call("stop-fresh-host", "daemon", "stop", "--confirm", timeout=20)
        check("freshHostActualExit", host.wait(timeout=20) == 0)
        host_operation.update(complete=True, exitCode=host.returncode, durationSeconds=round(time.monotonic() - host_operation.pop("startedMonotonic"), 4))
        host = None
        recovered = public_database(profile)
        check("logoutFenceSurvivesRestart", recovered["generation"] == fenced["generation"]
              and recovered["locked"] and recovered["intentAbsent"]
              and all(not p["consent"] for p in recovered["projects"].values())
              and all(recovered["outbox"].get(w) is False for w in ids)
              and recovered["schemaClean"])
        stopped = True
    except BaseException as error:
        report["errorClass"] = type(error).__name__
    finally:
        if stall is not None:
            try:
                stall.close()
            except BaseException as error:
                report["cleanup"]["stallErrorClass"] = type(error).__name__
        if host is not None:
            try:
                require_unreaped_child(host)
                status = os.waitid(os.P_PID, host.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                try:
                    if status is None:
                        call("failure-controlled-stop", "daemon", "stop", "--confirm", timeout=20)
                    code = host.wait(timeout=20)
                    report["cleanup"]["failureControlledHostExit"] = code == 0
                    if code == 0:
                        workload_cleanup_known = True
                except BaseException as error:
                    report["cleanup"]["controlledStopErrorClass"] = type(error).__name__
                    # A retained Popen child, never a discovered/stale PID, is
                    # the only authority for the bounded fallback signal.
                    if host.returncode is None:
                        require_unreaped_child(host)
                        stop_group(host)
                        report["cleanup"]["ownedHostForcedExitConfirmed"] = host.returncode is not None
                host_operation.update(complete=True, exitCode=host.returncode, durationSeconds=round(time.monotonic() - host_operation.pop("startedMonotonic"), 4))
            except BaseException as error:
                report["cleanup"]["hostErrorClass"] = type(error).__name__
        report["cleanup"]["attachExitKnown"] = attach_cleanup_known
        report["cleanup"]["hostWorkloadsExitKnown"] = workload_cleanup_known
        cleanup_safe = (host is None or host.returncode is not None) and attach_cleanup_known and workload_cleanup_known
        if private is not None and cleanup_safe:
            shutil.rmtree(private)
            report["cleanup"]["privateInputsRemoved"] = not private.exists()
        else:
            report["cleanup"]["privateInputsRemoved"] = False
        report["cleanup"]["controlledProductStop"] = stopped
        try:
            after = source_inventory(ROOT)
            report["sourceAfter"] = after
            report["checks"]["sourcesUnchanged"] = before == after
        except BaseException as error:
            report["cleanup"]["sourceErrorClass"] = type(error).__name__
        report["passed"] = (stopped and report["cleanup"].get("privateInputsRemoved", False)
                            and "errorClass" not in report and all(report["checks"].values()))
        persist()
    print(json.dumps({"passed": report["passed"], "report": str(report_path.relative_to(ROOT))}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
