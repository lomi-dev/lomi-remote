#!/usr/bin/env python3
"""Actual product controller-death negative; operator cleanup is a separate proof."""
import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pwd
from pathlib import Path
import plistlib
import select
import stat
import subprocess
import sys
import time
import uuid

import build
import run_native as happy
from build import MINIMAL, freeze_build, sha, verify
from owned_process import initialize_process_ownership, run_owned

BASE = Path.home() / ".lomi-pty-build"
RUNTIME = Path.home() / ".lomi-pty"
LIBC = ctypes.CDLL(None, use_errno=True)


def reject_acl(fd):
    LIBC.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    LIBC.acl_get_fd_np.restype = ctypes.c_void_p
    LIBC.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    LIBC.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    LIBC.acl_free.argtypes = [ctypes.c_void_p]
    acl = LIBC.acl_get_fd_np(fd, 0x100)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise RuntimeError("acl_unavailable")
    try:
        selector = 0
        while True:
            entry = ctypes.c_void_p()
            if LIBC.acl_get_entry(acl, selector, ctypes.byref(entry)):
                if ctypes.get_errno() == errno.EINVAL:
                    return
                raise RuntimeError("acl_entry_unavailable")
            tag = ctypes.c_int()
            if LIBC.acl_get_tag_type(entry, ctypes.byref(tag)) or tag.value != 2:
                raise RuntimeError("acl_grant_refused")
            selector = -1
    finally:
        LIBC.acl_free(acl)


def directory(path, private=True):
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise RuntimeError("absolute_directory_required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    current = Path("/")
    try:
        reject_acl(fd)
        for component in path.parts[1:]:
            current /= component
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            metadata = os.fstat(child)
            special = current == Path("/private/tmp") and metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o1777
            if metadata.st_uid not in (0, os.geteuid()) or (metadata.st_mode & 0o022 and not special):
                os.close(child)
                raise RuntimeError("directory_ancestry_refused")
            reject_acl(child)
            os.close(fd)
            fd = child
        metadata = os.fstat(fd)
        if private and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
            raise RuntimeError("private_directory_required")
        return fd
    except BaseException:
        os.close(fd)
        raise


def pin(metadata):
    return [metadata.st_dev, metadata.st_ino]


def read_file(path, private=True):
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 or (private and stat.S_IMODE(metadata.st_mode) != 0o600):
                raise RuntimeError("regular_file_refused")
            reject_acl(stream.fileno())
            data = stream.read(131073)
            if len(data) > 131072:
                raise RuntimeError("file_limit")
            return data, pin(metadata)
    finally:
        os.close(parent)


def save(root, name, value):
    happy.save(root, name, value)


def observe(root, record, folder):
    target = "user/" + str(os.geteuid()) + "/dev.lomi.pty." + record["run"].replace("-", "")
    result = run_owned(["/bin/launchctl", "print", target], env=MINIMAL, timeout=5)
    if len(result.stdout) > 32768 or len(result.stderr) > 32768:
        raise RuntimeError("manager_output_limit")
    if result.returncode == 113:
        return None
    if result.returncode:
        raise RuntimeError("manager_unavailable")
    return parse_job(result.stdout, target, record["executable"], folder)


def parse_job(output, target, executable, folder):
    lines = output.splitlines()
    if not lines or lines[0] != target + " = {":
        raise RuntimeError("manager_identity_refused")
    for key, wanted in (("path", str(folder / "job.plist")), ("program", executable)):
        if [line[len("\t" + key + " = "):] for line in lines if line.startswith("\t" + key + " = ")] != [wanted]:
            raise RuntimeError("manager_definition_refused")
    starts = [i for i, line in enumerate(lines) if line == "\targuments = {"]
    if len(starts) != 1 or lines[starts[0] + 1:starts[0] + 5] != ["\t\t" + executable, "\t\t--internal-pty-coalition", "\t\t" + str(folder), "\t}"]:
        raise RuntimeError("manager_arguments_refused")
    pids = [line[len("\tpid = "):] for line in lines if line.startswith("\tpid = ")]
    if not pids:
        return {"pid": None}
    if len(pids) != 1 or not pids[0].isascii() or not pids[0].isdigit() or int(pids[0]) <= 0:
        raise RuntimeError("manager_pid_refused")
    return {"pid": int(pids[0])}


def require_certificate(record, proof, host_proof, workload_pid):
    if record["stage"] == "Cleaned" or record.get("drained") is not False or record.get("admissionConsumed") is not True:
        raise RuntimeError("negative_product_state_missing")
    required = ("allRegistrationsAccepted", "sameControllerAuditSignal", "controllerNoteExit", "workloadNoteExit", "fixtureGenerationProcessesGone")
    if proof.get("schema") != 1 or proof.get("nonce") != record["nonce"] or proof.get("controllerPid") != record["controller"]["pid"] or type(workload_pid) is not int or workload_pid <= 0 or proof.get("workloadPid") != workload_pid or proof.get("hostPid") != record["host"]["pid"] or proof.get("initialLiveCount") != 2 or proof.get("numericSignalsUsed") is not False or not all(proof.get(key) is True for key in required):
        raise RuntimeError("generation_death_certificate_refused")
    if host_proof != {"schema": 1, "nonce": record["nonce"], "hostPid": record["host"]["pid"], "hostNoteExit": True, "fixtureAllThreeProcessesGone": True}:
        raise RuntimeError("host_death_certificate_refused")


def require_live_orphan(proof):
    if proof.get("workloadLiveAfterControllerNoteExit") is not True:
        raise RuntimeError("post_controller_live_workload_unproven")


def verify_driver(root):
    source = root / "driver-source"
    manifest_path = root / "driver-source-manifest.json"
    if not manifest_path.exists():
        return  # Ordinary runs execute the driver inside verified inputs.
    reuse = json.loads(read_file(root / "production-reuse.json")[0])
    if sha(manifest_path) != reuse["driverManifestSha256"]:
        raise RuntimeError("driver_manifest_binding_refused")
    expected = json.loads(read_file(manifest_path)[0])
    names = {"tests/product-pty-macos/" + name + ".py" for name in ("controller_death", "build", "run_native", "test_controller_death")} | {"tools/owned_process.py", "tools/macos_service_build.py"}
    if set(expected) != names or Path(__file__).resolve() != source / "tests/product-pty-macos/controller_death.py":
        raise RuntimeError("driver_schema_or_entry_refused")
    for name, item in expected.items():
        path = source / name
        data, _ = read_file(path, private=False)
        if hashlib.sha256(data).hexdigest() != item["sha256"] or stat.S_IMODE(path.lstat().st_mode) != item["mode"] or item["mode"] != 0o400:
            raise RuntimeError("frozen_driver_changed")


def frozen_checks(root):
    original = json.loads((root / "build-receipt.json").read_text())
    cargo = original["command"][0]
    environment = {**original["environment"], "HOME": pwd.getpwuid(os.geteuid()).pw_dir,
                   "CARGO": cargo, "PATH": str(Path(cargo).parent) + ":" + MINIMAL["PATH"]}
    checks = {"passed": False, "inputManifestSha256": sha(root / "input-manifest.json"), "environment": environment, "checks": []}
    save(root, "controller-checks.json", checks)
    commands = [("acceptance", [sys.executable, "-B", "-m", "unittest", "discover", "-s", str(Path(__file__).parent), "-p", "test_controller_death.py", "-v"]),
                ("clippy", [cargo, "clippy", "--locked", "--offline", "-p", "lomi-terminal", "--bin", "lomi-pty-macos-coalition-fixture", "--features", "experimental-macos-coalition-cleanup", "--", "-D", "warnings"])]
    for name, command in commands:
        result = run_owned(command, cwd=root / "inputs", env=environment, timeout=180)
        item = {"name": name, "command": command, "cwd": str(root / "inputs"), "exit": result.returncode}
        for kind, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = root / ("controller-check-" + name + "." + kind + ".log")
            path.write_text(data)
            path.chmod(0o600)
            item[kind + "Sha256"] = sha(path)
        checks["checks"].append(item)
        save(root, "controller-checks.json", checks)
        if result.returncode:
            raise RuntimeError("frozen_check_failed")
    verify(root)
    checks["passed"] = True
    save(root, "controller-checks.json", checks)


def compile_observer(root):
    verify(root)
    original = json.loads((root / "build-receipt.json").read_text())
    tools = json.loads((root / "tools.json").read_text())
    source = root / "inputs/tests/product-pty-macos/controller_observer.c"
    executable = root / "bin/controller-observer"
    command = [tools["clang"]["path"], "-std=c11", "-Wall", "-Wextra", "-Werror", "-isysroot", original["environment"]["SDKROOT"], str(source), "-lbsm", "-o", str(executable)]
    if executable.exists() or executable.is_symlink() or sha(Path(command[0])) != tools["clang"]["sha256"] or sha(Path(original["environment"]["SDKROOT"]) / "SDKSettings.json") != tools["sdk"]["settingsSha256"]:
        raise RuntimeError("observer_build_inputs_refused")
    result = run_owned(command, env=original["environment"], timeout=30)
    receipt = {"passed": False, "command": command, "environment": original["environment"], "exit": result.returncode, "sourceSha256": sha(source), "inputManifestSha256": sha(root / "input-manifest.json"), "clangSha256": sha(Path(command[0])), "sdkSettingsSha256": tools["sdk"]["settingsSha256"]}
    for kind, data in (("stdout", result.stdout), ("stderr", result.stderr)):
        path = root / ("observer-build." + kind + ".log")
        path.write_text(data)
        path.chmod(0o600)
        receipt[kind + "Sha256"] = sha(path)
    if result.returncode:
        save(root, "observer-build.json", receipt)
        raise RuntimeError("observer_build_failed")
    executable.chmod(0o500)
    receipt["binarySha256"] = sha(executable)
    verify(root)
    receipt["passed"] = True
    save(root, "observer-build.json", receipt)
    return executable


def verify_observer(root):
    receipt = json.loads(read_file(root / "observer-build.json")[0])
    if receipt.get("passed") is not True or receipt["inputManifestSha256"] != sha(root / "input-manifest.json") or receipt["sourceSha256"] != sha(root / "inputs/tests/product-pty-macos/controller_observer.c") or receipt["binarySha256"] != sha(root / "bin/controller-observer"):
        raise RuntimeError("observer_receipt_binding_refused")


def wait_line(child, wanted, timeout):
    ready, _, _ = select.select([child.stdout], [], [], timeout)
    if not ready or child.stdout.readline().strip() != wanted:
        raise RuntimeError("observer_handshake_refused")


def _allowed_paths(record):
    generation = ("Library", "Application Support", "LomiRemote", "pty-generations", record["run"])
    allowed_dirs = {(), *(generation[:i] for i in range(1, 6))}
    root_files = {"fault-nofork.pid", "fault-nofork.heartbeat", "host.ready", "fault.injected", "operator.release", "host.negative.json"}
    allowed_files = {*( (name,) for name in root_files), generation[:3] + ("pty-operations.lock",), *(generation + (name,) for name in ("journal.json", "journal.lock", "owner.lock", "controller.lock", "job.plist"))}
    return allowed_dirs, allowed_files


def _private_runtime_directory(parts):
    return tuple(parts) not in (("Library",), ("Library", "Application Support"))


def quiescent_manager_state(state):
    if state is None:
        return "absent"
    if state == {"pid": None}:
        return "loadedWithoutPid"
    raise RuntimeError("manager_still_has_live_pid")


def _runtime_manifest(runtime, record):
    allowed_dirs, allowed_files = _allowed_paths(record)
    generation = ("Library", "Application Support", "LomiRemote", "pty-generations", record["run"])
    files, directories = [], []
    for path, child_dirs, child_files in os.walk(runtime, followlinks=False):
        node = Path(path)
        relative = tuple(node.relative_to(runtime).parts)
        if relative not in allowed_dirs:
            raise RuntimeError("unknown_runtime_directory")
        fd = directory(node, private=_private_runtime_directory(relative))
        try:
            if os.fstat(fd).st_uid != os.geteuid():
                raise RuntimeError("runtime_directory_owner_refused")
            directories.append({"path": list(relative), "pin": pin(os.fstat(fd))})
        finally:
            os.close(fd)
        for name in child_dirs:
            if relative + (name,) not in allowed_dirs:
                raise RuntimeError("unknown_runtime_directory")
        for name in child_files:
            parts = relative + (name,)
            if parts not in allowed_files:
                raise RuntimeError("unknown_runtime_file")
            private = name in {"journal.json", "journal.lock", "owner.lock", "controller.lock", "job.plist", "pty-operations.lock", "fault.injected", "operator.release"}
            data, identity = read_file(node / name, private=private)
            files.append({"path": list(parts), "pin": identity, "private": private, "hex": data.hex()})
    if not any(item["path"] == list(generation + ("journal.json",)) for item in files):
        raise RuntimeError("original_generation_missing")
    return {"files": files, "directories": directories}


def _validate_manifest(manifest, record, runtime_pin, unknown_sha):
    allowed_dirs, allowed_files = _allowed_paths(record)
    if not isinstance(manifest, dict) or set(manifest) != {"files", "directories"} or not isinstance(manifest["files"], list) or not isinstance(manifest["directories"], list) or len(manifest["files"]) > len(allowed_files) or len(manifest["directories"]) != len(allowed_dirs):
        raise RuntimeError("manifest_schema_refused")
    dirs, files = {}, {}
    for item in manifest["directories"]:
        parts = tuple(item["path"])
        if parts not in allowed_dirs or parts in dirs or not _pin(item["pin"]):
            raise RuntimeError("manifest_directory_refused")
        dirs[parts] = item
    generation = ("Library", "Application Support", "LomiRemote", "pty-generations", record["run"])
    if set(dirs) != allowed_dirs or dirs[()]["pin"] != runtime_pin or dirs[generation]["pin"] != record["generationPin"] or dirs[generation[:3]]["pin"] != record["profilePin"]:
        raise RuntimeError("manifest_directory_identity_refused")
    for item in manifest["files"]:
        parts = tuple(item["path"])
        if parts not in allowed_files or parts in files or not _pin(item["pin"]) or not isinstance(item["hex"], str) or len(item["hex"]) > 262144:
            raise RuntimeError("manifest_file_refused")
        private = parts[-1] in {"journal.json", "journal.lock", "owner.lock", "controller.lock", "job.plist", "pty-operations.lock", "fault.injected", "operator.release"}
        if item["private"] is not private:
            raise RuntimeError("manifest_file_mode_refused")
        data = bytes.fromhex(item["hex"])
        if parts[-1] in {"journal.lock", "owner.lock", "controller.lock", "pty-operations.lock"} and data:
            raise RuntimeError("manifest_nonempty_lock")
        files[parts] = item
    required = {*(generation + (name,) for name in ("journal.json", "journal.lock", "owner.lock", "controller.lock", "job.plist")), generation[:3] + ("pty-operations.lock",)}
    if not required <= set(files) or files[generation + ("controller.lock",)]["pin"] != record["lifetime"] or hashlib.sha256(bytes.fromhex(files[generation + ("journal.json",)]["hex"])).hexdigest() != unknown_sha:
        raise RuntimeError("manifest_generation_proof_refused")


def _pin(value):
    return isinstance(value, list) and len(value) == 2 and all(type(n) is int and n > 0 for n in value)


def _intent(value):
    runtime = Path(value["runtime"])
    if runtime.parent != RUNTIME or not happy.re_runtime(runtime.name) or not _pin(value["runtimePin"]) or not _pin(value["runLockPin"]):
        raise RuntimeError("runtime_identity_refused")
    if value.get("run") is not None and str(uuid.UUID(value["run"])) != value["run"]:
        raise RuntimeError("generation_uuid_refused")
    return runtime


def _remaining_manifest(runtime, manifest):
    directories = {tuple(item["path"]): item for item in manifest["directories"]}
    files = {tuple(item["path"]): item for item in manifest["files"]}
    for parts, item in sorted(directories.items(), key=lambda pair: len(pair[0])):
        node = runtime.joinpath(*parts)
        try:
            metadata = node.lstat()
        except FileNotFoundError:
            continue  # Durable deletion intent authorizes absence on retry.
        if not stat.S_ISDIR(metadata.st_mode) or pin(metadata) != item["pin"]:
            raise RuntimeError("remaining_directory_pin_refused")
        fd = directory(node, private=_private_runtime_directory(parts))
        try:
            if os.fstat(fd).st_uid != os.geteuid():
                raise RuntimeError("runtime_directory_owner_refused")
            expected = {key[-1] for key in (*directories, *files) if key and key[:-1] == parts}
            if set(os.listdir(fd)) - expected:
                raise RuntimeError("unexpected_remaining_entry")
        finally:
            os.close(fd)
    for parts, item in files.items():
        node = runtime.joinpath(*parts)
        try:
            node.lstat()
        except FileNotFoundError:
            continue
        if read_file(node, private=item["private"]) != (bytes.fromhex(item["hex"]), item["pin"]):
            raise RuntimeError("remaining_file_changed")


def operator_cleanup(root, owned_lock=None):
    intent_path = root / "controller-fault-intent.json"
    if not intent_path.exists():
        return True
    intent = json.loads(read_file(intent_path)[0])
    runtime = _intent(intent)
    data, lock_pin = read_file(root / "controller-fault.lock")
    if data or lock_pin != intent["runLockPin"]:
        raise RuntimeError("run_lock_identity_refused")
    lock = owned_lock
    if lock is not None and pin(os.fstat(lock)) != lock_pin:
        raise RuntimeError("held_run_lock_identity_refused")
    close_lock = False
    if lock is None:
        lock = os.open(root / "controller-fault.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        close_lock = True
        if pin(os.fstat(lock)) != intent["runLockPin"]:
            os.close(lock)
            raise RuntimeError("run_lock_pin_refused")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    handles = []
    try:
        pending_path = root / "operator-cleanup-intent.json"
        if pending_path.exists():
            pending = json.loads(read_file(pending_path)[0])
            record = json.loads(read_file(root / "unknown.journal.json")[0])
        else:
            if not intent.get("run"):
                raise RuntimeError("pre_admission_recovery_requires_product_proof")
            folder = runtime / "Library/Application Support/LomiRemote/pty-generations" / intent["run"]
            data, _ = read_file(folder / "journal.json")
            record = json.loads(data)
            if record["stage"] == "Cleaned":
                raise RuntimeError("negative_case_became_cleaned")
            # Save exact bytes even when the driver was interrupted before it
            # could preserve its first Unknown snapshot.
            unknown = root / "unknown.journal.json"
            if not unknown.exists():
                fd = os.open(unknown, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    os.write(fd, data)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                fd = directory(root)
                os.fsync(fd)
                os.close(fd)
            if read_file(unknown)[0] != data:
                raise RuntimeError("unknown_journal_changed")
            deadline = time.monotonic() + 50
            while not (root / "observer-processes.json.host.json").exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("independent_death_proof_unavailable")
                time.sleep(0.02)
            proof = json.loads(read_file(root / "observer-processes.json")[0])
            host_proof = json.loads(read_file(root / "observer-processes.json.host.json")[0])
            require_certificate(record, proof, host_proof, intent["workloadPid"])
            if proof["workloadPid"] != intent["workloadPid"] or record["nonce"] != intent["nonce"] or record["controller"] != intent["controller"] or record["host"] != intent["host"]:
                raise RuntimeError("original_identity_changed")
            fd = directory(runtime)
            if pin(os.fstat(fd)) != intent["runtimePin"]:
                os.close(fd)
                raise RuntimeError("runtime_pin_refused")
            os.close(fd)
            profile = folder.parent.parent
            fd = directory(profile)
            if pin(os.fstat(fd)) != record["profilePin"]:
                os.close(fd)
                raise RuntimeError("profile_pin_refused")
            os.close(fd)
            fd = directory(folder)
            if pin(os.fstat(fd)) != record["generationPin"]:
                os.close(fd)
                raise RuntimeError("generation_pin_refused")
            os.close(fd)
            namespace = Path("/private/tmp") / ("lomi-pty-" + str(os.geteuid()) + "-" + record["run"])
            fd = directory(namespace)
            metadata = os.stat("s", dir_fd=fd, follow_symlinks=False)
            if pin(os.fstat(fd)) != record["runtimePin"] or os.listdir(fd) != ["s"] or not stat.S_ISSOCK(metadata.st_mode) or pin(metadata) != record["socketPin"] or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
                os.close(fd)
                raise RuntimeError("namespace_or_socket_pin_refused")
            os.close(fd)
            plist = plistlib.loads(read_file(folder / "job.plist")[0])
            expected = {"Label": "dev.lomi.pty." + record["run"].replace("-", ""), "ProgramArguments": [record["executable"], "--internal-pty-coalition", str(folder)], "RunAtLoad": True, "LaunchOnlyOnce": True, "KeepAlive": False, "LimitLoadToSessionType": "Background", "ProcessType": "Background", "ExitTimeOut": 3, "Umask": 63, "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"}
            if plist != expected:
                raise RuntimeError("exact_plist_refused")
            pending = {"schema": 1, "run": record["run"], "nonce": record["nonce"], "runtime": str(runtime), "runtimePin": intent["runtimePin"], "unknownJournalSha256": sha(unknown), "proofSha256": sha(root / "observer-processes.json"), "hostProofSha256": sha(root / "observer-processes.json.host.json"), "manifest": _runtime_manifest(runtime, record)}
            # This intent is durable BEFORE bootout or any unlink. Missing
            # entries are subsequently authorized only by this exact manifest.
            _validate_manifest(pending["manifest"], record, intent["runtimePin"], pending["unknownJournalSha256"])
            pending["exactJobStateBeforeOperator"] = quiescent_manager_state(observe(root, record, folder))
            save(root, "operator-cleanup-intent.json", pending)
        if pending.get("exactJobStateBeforeOperator") not in ("absent", "loadedWithoutPid") or pending.get("schema") != 1 or pending["run"] != record["run"] or pending["nonce"] != record["nonce"] or pending["runtime"] != str(runtime) or pending["runtimePin"] != intent["runtimePin"] or pending["unknownJournalSha256"] != sha(root / "unknown.journal.json") or pending["proofSha256"] != sha(root / "observer-processes.json") or pending["hostProofSha256"] != sha(root / "observer-processes.json.host.json"):
            raise RuntimeError("operator_intent_refused")
        require_certificate(record, json.loads(read_file(root / "observer-processes.json")[0]), json.loads(read_file(root / "observer-processes.json.host.json")[0]), intent["workloadPid"])
        if record["run"] != intent["run"] or record["nonce"] != intent["nonce"] or record["controller"] != intent["controller"] or record["host"] != intent["host"]:
            raise RuntimeError("retained_original_identity_refused")
        folder = runtime / "Library/Application Support/LomiRemote/pty-generations" / record["run"]
        namespace = Path("/private/tmp") / ("lomi-pty-" + str(os.geteuid()) + "-" + record["run"])
        _validate_manifest(pending["manifest"], record, intent["runtimePin"], pending["unknownJournalSha256"])
        _remaining_manifest(runtime, pending["manifest"])
        # Retain the exact existing lock inodes throughout operator mutation.
        for path in (folder / "owner.lock", folder / "controller.lock", folder.parent.parent / "pty-operations.lock"):
            if path.exists():
                data, identity = read_file(path)
                fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                if data or pin(os.fstat(fd)) != identity or (path.name == "controller.lock" and identity != record["lifetime"]):
                    os.close(fd)
                    raise RuntimeError("lifetime_pin_refused")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                handles.append(fd)
        state = observe(root, record, folder)
        quiescent_manager_state(state)
        target = "user/" + str(os.geteuid()) + "/dev.lomi.pty." + record["run"].replace("-", "")
        if state is not None:
            result = run_owned(["/bin/launchctl", "bootout", target], env=MINIMAL, timeout=5)
            if result.returncode and observe(root, record, folder) is not None:
                raise RuntimeError("operator_exact_bootout_failed")
        if observe(root, record, folder) is not None:
            raise RuntimeError("operator_job_absence_unconfirmed")
        override = run_owned(["/bin/launchctl", "print-disabled", "user/" + str(os.geteuid())], env=MINIMAL, timeout=5)
        label = target.split("/")[-1]
        if override.returncode or any(line.strip().startswith('"' + label + '" => ') for line in override.stdout.splitlines()):
            raise RuntimeError("override_changed")
        try:
            fd = directory(namespace)
        except FileNotFoundError:
            fd = None
        if fd is not None:
            try:
                if pin(os.fstat(fd)) != record["runtimePin"] or set(os.listdir(fd)) - {"s"}:
                    raise RuntimeError("remaining_namespace_refused")
                if "s" in os.listdir(fd):
                    metadata = os.stat("s", dir_fd=fd, follow_symlinks=False)
                    if not stat.S_ISSOCK(metadata.st_mode) or pin(metadata) != record["socketPin"] or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
                        raise RuntimeError("remaining_socket_refused")
                    os.unlink("s", dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rmdir(namespace)
        fd = directory(Path("/private/tmp"), private=False)
        os.fsync(fd)
        os.close(fd)
        for item in pending["manifest"]["files"]:
            node = runtime.joinpath(*item["path"])
            try:
                node.lstat()
            except FileNotFoundError:
                continue
            if read_file(node, private=item["private"]) != (bytes.fromhex(item["hex"]), item["pin"]):
                raise RuntimeError("file_changed_during_operator_cleanup")
            node.unlink()
            fd = directory(node.parent, private=False)
            os.fsync(fd)
            os.close(fd)
        for item in sorted(pending["manifest"]["directories"], key=lambda item: len(item["path"]), reverse=True):
            node = runtime.joinpath(*item["path"])
            try:
                metadata = node.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(metadata.st_mode) or pin(metadata) != item["pin"]:
                raise RuntimeError("directory_changed_during_operator_cleanup")
            node.rmdir()
            fd = directory(node.parent, private=False)
            os.fsync(fd)
            os.close(fd)
        cleanup = {"operatorDriverSha256": sha(Path(__file__)), "cleanupConfirmed": True, "productCleanupSucceeded": False, "originalProductStage": record["stage"], "unknownJournalSha256": sha(root / "unknown.journal.json"), "run": record["run"], "nonce": record["nonce"], "operatorIntentSha256": sha(pending_path), "proofSha256": pending["proofSha256"], "hostProofSha256": pending["hostProofSha256"], "operatorExactJobAbsent": True, "exactJobStateBeforeOperator": pending["exactJobStateBeforeOperator"], "numericSignalsUsed": False, "job": "absent", "profile": "absent", "socketNamespace": "absent", "override": None}
        save(root, "operator-cleanup.json", cleanup)
        return True
    finally:
        for fd in handles:
            os.close(fd)
        if close_lock:
            os.close(lock)


def native(root):
    if root.parent != BASE or str(uuid.UUID(root.name)) != root.name:
        raise RuntimeError("artifact_root_refused")
    root_fd = directory(root)
    os.close(root_fd)
    verify(root)
    verify_driver(root)
    if (root / "controller-fault-intent.json").exists():
        raise RuntimeError("artifact_generation_already_consumed")
    lock = os.open(root / "controller-fault.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.fsync(lock)
    frozen_checks(root)
    observer = compile_observer(root)
    binary = root / "bin/pty-fixture"
    preflight = run_owned([str(observer), "--preflight"], env=MINIMAL, timeout=5)
    if preflight.returncode or preflight.stdout != "SDK_PREFLIGHT_AVAILABLE\n":
        raise RuntimeError("observer_preflight_unavailable")
    disk = os.statvfs(root)
    if disk.f_bavail * disk.f_frsize < 1.5 * 2**30:
        raise RuntimeError("native_disk_floor_refused")
    happy.private_base(RUNTIME)
    runtime = RUNTIME / uuid.uuid4().hex[:16]
    runtime.mkdir(mode=0o700)
    runtime_fd = directory(runtime)
    runtime_pin = pin(os.fstat(runtime_fd))
    os.close(runtime_fd)
    report = {"buildReceiptSha256": sha(root / "build-receipt.json"), "inputManifestSha256": sha(root / "input-manifest.json"), "observerBuildSha256": sha(root / "observer-build.json"), "checksReceiptSha256": sha(root / "controller-checks.json"), "passed": False, "negativeAcceptance": True, "productCleanupSucceeded": False, "operatorCleanupConfirmed": False, "qualifiedProductRelease": False, "runtime": str(runtime), "binarySha256": sha(binary), "observerSha256": sha(observer)}
    save(root, "controller-death-evidence.json", report)
    save(root, "controller-fault-intent.json", {"runtime": str(runtime), "runtimePin": runtime_pin, "runLockPin": pin(os.fstat(lock)), "run": None})
    host = subprocess.Popen([str(binary), "controller-death", str(runtime)], env=MINIMAL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    watch = None
    try:
        deadline = time.monotonic() + 10
        while not (runtime / "host.ready").exists():
            if os.waitid(os.P_PID, host.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None or time.monotonic() >= deadline:
                raise RuntimeError("actual_pty_unready")
            time.sleep(0.01)
        base = runtime / "Library/Application Support/LomiRemote/pty-generations"
        folders = list(base.iterdir())
        if len(folders) != 1:
            raise RuntimeError("generation_count_refused")
        folder = folders[0]
        record_bytes, _ = read_file(folder / "journal.json")
        record = json.loads(record_bytes)
        if record["run"] != str(uuid.UUID(folder.name)) or record["stage"] != "AdmissionConsumed" or record["admissionConsumed"] is not True or record["workerStep"] != "Acquired" or record["host"]["pid"] != host.pid:
            raise RuntimeError("actual_grant_unconfirmed")
        if observe(root, record, folder) != {"pid": record["controller"]["pid"]}:
            raise RuntimeError("manager_controller_identity_refused")
        leader = int(read_file(runtime / "fault-nofork.pid", private=False)[0])
        intent = {"runtime": str(runtime), "runtimePin": runtime_pin, "runLockPin": pin(os.fstat(lock)), "run": record["run"], "nonce": record["nonce"], "controller": record["controller"], "host": record["host"], "workloadPid": leader}
        save(root, "controller-fault-intent.json", intent)
        happy.save(root, "admitted.journal.json", record)
        args = [str(observer), str(root / "observer-processes.json"), str(record["controller"]["pid"]), str(leader), *map(str, record["controller"]["audit"]), str(record["controller"]["resource"]), str(record["controller"]["jetsam"]), record["nonce"], str(binary), str(host.pid), *map(str, record["host"]["audit"]), str(record["host"]["resource"]), str(record["host"]["jetsam"]), str(runtime)]
        save(root, "observer-request.json", {"command": args, "environment": MINIMAL, "binarySha256": sha(observer), "inputManifestSha256": sha(root / "input-manifest.json")})
        watch = subprocess.Popen(args, env=MINIMAL, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        wait_line(watch, "OBSERVER_READY", 5)
        # All audit/token/count/SDK registrations have succeeded before the only
        # destructive fault. Durable intent predates the one-way instruction.
        watch.stdin.write("K")
        watch.stdin.flush()
        watch.stdin.close()
        watch.stdin = None
        wait_line(watch, "CONTROLLER_EXIT_OBSERVED", 5)
        deadline = time.monotonic() + 10
        while not (runtime / "host.negative.json").exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("product_negative_result_missing")
            time.sleep(0.01)
        negative = json.loads(read_file(runtime / "host.negative.json", private=False)[0])
        unknown_bytes, _ = read_file(folder / "journal.json")
        unknown = json.loads(unknown_bytes)
        if any(value in unknown_bytes for value in (b"--workload", b"LOMI_FIXTURE_PROTECTED", b"never-persist-this-fixture-value")):
            raise RuntimeError("protected_payload_persisted")
        if unknown_bytes != record_bytes or unknown["stage"] == "Cleaned" or unknown["drained"] is not False:
            raise RuntimeError("unknown_ownership_lost")
        output = root / "unknown.journal.json"
        output.write_bytes(unknown_bytes)
        output.chmod(0o600)
        with output.open("rb") as stream:
            os.fsync(stream.fileno())
        root_fd = directory(root)
        os.fsync(root_fd)
        os.close(root_fd)
        expected_reservations = {"realUncertainGenerations": 1, "syntheticHeldPreparedReservations": 31, "reservationGateRejectedAt32": True, "finalFenceCalled": False, "originalJournalUnchanged": True, "noAdditionalGeneration": True, "syntheticReservationsRemoved": True, "is32RunningJobQualification": False}
        if negative != {"shutdownReportedCleanupFailure": True, "recoveryReportedUncertainty": True, "reservations": expected_reservations}:
            raise RuntimeError("product_negative_expectations_failed")
        stdout, stderr = watch.communicate(timeout=30)
        (root / "observer.stdout.log").write_text("OBSERVER_READY\nCONTROLLER_EXIT_OBSERVED\n" + stdout)
        (root / "observer.stderr.log").write_text(stderr)
        if watch.returncode or stdout != "BOTH_EXIT_OBSERVED\nALL_EXIT_OBSERVED\n" or stderr:
            raise RuntimeError("retained_observer_failed")
        stdout, stderr = host.communicate(timeout=5)
        (root / "host-fault.stdout.log").write_text(stdout)
        (root / "host-fault.stderr.log").write_text(stderr)
        if host.returncode or stdout or stderr:
            raise RuntimeError("fixture_host_failed")
        # Product remains uncertain even after source-known processes are gone.
        before = read_file(folder / "journal.json")[0]
        for command, expected_exit in (([str(binary), "recover", str(runtime)], 4), ([str(binary), "--internal-pty-coalition", str(folder)], 1)):
            result = run_owned(command, env=MINIMAL, timeout=10)
            if result.returncode != expected_exit or result.stdout or result.stderr or read_file(folder / "journal.json")[0] != before:
                raise RuntimeError("product_recovery_replayed_or_cleaned")
        manager_state = quiescent_manager_state(observe(root, record, folder))
        require_live_orphan(json.loads(read_file(root / "observer-processes.json")[0]))
        report["observerRequestSha256"] = sha(root / "observer-request.json")
        report.update(actualPtyOutputObserved=True, actualAdmissionConsumed=True, negativeChecks=negative,
                      productUnknownAfterAllFixtureProcessesGone=True, managerStateAfterUnknown=manager_state,
                      managerAbsenceIsProductCleanupProof=False,
                      productBootoutExcludedByReviewedSource={"sourceSha256": sha(root / "inputs/crates/lomi-terminal/src/supervisor/macos_coalition.rs"), "gate": "finalize_requires_Closing_disposed_leaderReaped_drained_before_manager_remove"},
                      noReplayObserved=True, unknownJournalSha256=sha(output))
        report["passed"] = True
    finally:
        # Never kill the independent observer. Its fixed fixture deadlines and
        # cooperative host release complete the bound exit certificate even if
        # the Python driver is interrupted after K.
        if watch is not None and watch.returncode is None:
            if watch.stdin is not None:
                watch.stdin.close()
                watch.stdin = None
            try:
                watch.communicate(timeout=50)
            except subprocess.TimeoutExpired:
                pass
        if host.returncode is None:
            try:
                host.communicate(timeout=55)
            except subprocess.TimeoutExpired:
                pass
        try:
            report["operatorCleanupConfirmed"] = operator_cleanup(root, owned_lock=lock)
        except BaseException:
            report["operatorCleanupConfirmed"] = False
        verify(root)
        verify_observer(root)
        verify_driver(root)
        if (root / "production-reuse.json").exists():
            report["productionReuseReceiptSha256"] = sha(root / "production-reuse.json")
            report["driverManifestSha256"] = sha(root / "driver-source-manifest.json")
        if report["operatorCleanupConfirmed"]:
            report["operatorCleanupReceiptSha256"] = sha(root / "operator-cleanup.json")
            report["generationDeathProofSha256"] = sha(root / "observer-processes.json")
            report["hostDeathProofSha256"] = sha(root / "observer-processes.json.host.json")
        report["passed"] = report["passed"] and report["operatorCleanupConfirmed"]
        save(root, "controller-death-evidence.json", report)
        print(root / "controller-death-evidence.json")
        os.close(lock)
    return report["passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true")
    parser.add_argument("--frozen-run", type=Path)
    args = parser.parse_args()
    if not args.run_native or sys.platform != "darwin":
        parser.error("explicit --run-native on macOS required")
    initialize_process_ownership()
    if args.frozen_run:
        return 0 if native(args.frozen_run) else 1
    happy.private_base(BASE)
    root = BASE / str(uuid.uuid4())
    root.mkdir(mode=0o700)
    print("Controlled controller-death build: " + str(root), flush=True)
    freeze_build(Path(__file__).resolve().parents[2], root)
    verify(root)
    try:
        result = run_owned([sys.executable, "-B", str(root / "inputs/tests/product-pty-macos/controller_death.py"), "--run-native", "--frozen-run", str(root)], env=MINIMAL, timeout=300)
        for kind, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = root / ("controller-driver." + kind + ".log")
            path.write_text(data)
            path.chmod(0o600)
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode
    finally:
        # The same strict certificate permits outer process-interruption recovery.
        if (root / "controller-fault-intent.json").exists():
            operator_cleanup(root)


if __name__ == "__main__":
    sys.exit(main())
