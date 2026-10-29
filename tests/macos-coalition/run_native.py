#!/usr/bin/env python3
"""Experimental private-ABI coalition observations; never coalition ownership."""
import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import signal
import stat
import sys
import tarfile
import time
import uuid

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).parent if (Path(__file__).parent / "owned_process.py").is_file() else REPOSITORY / "tools"))
from owned_process import initialize_process_ownership, run_owned

BASE = Path.home() / ".lomi-coalition-artifacts"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
LIBC = ctypes.CDLL(None, use_errno=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
        raise RuntimeError("acl_query_failed")
    try:
        selector = 0
        while True:
            entry = ctypes.c_void_p()
            if LIBC.acl_get_entry(acl, selector, ctypes.byref(entry)):
                if ctypes.get_errno() == errno.EINVAL:
                    return
                raise RuntimeError("acl_entry_failed")
            tag = ctypes.c_int()
            if LIBC.acl_get_tag_type(entry, ctypes.byref(tag)) or tag.value != 2:
                raise RuntimeError("extended_acl_grant")
            selector = -1
    finally:
        LIBC.acl_free(acl)


def directory(path):
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise RuntimeError("absolute_directory_required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            metadata = os.fstat(child)
            if metadata.st_uid not in (0, os.geteuid()) or metadata.st_mode & 0o022:
                os.close(child)
                raise RuntimeError("writable_directory_ancestor")
            reject_acl(child)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_private(descriptor, name, limit=32768):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=descriptor)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
            raise RuntimeError("unsafe_owned_file")
        reject_acl(source.fileno())
        result = source.read(limit + 1)
        if len(result) > limit:
            raise RuntimeError("owned_file_limit")
        return result


def publish(descriptor, name, content):
    temporary = ".lomi-coalition-" + str(uuid.uuid4())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=descriptor)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        function = LIBC.renameatx_np
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        # Public SDK sys/stdio.h RENAME_EXCL=4; never replace an existing name.
        if function(descriptor, os.fsencode(temporary), descriptor, os.fsencode(name), 4):
            raise RuntimeError("exclusive_publication_failed")
        os.fsync(descriptor)
    finally:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass


def remove_exact(descriptor, name, expected):
    if read_private(descriptor, name) != expected:
        raise RuntimeError("owned_file_changed")
    os.unlink(name, dir_fd=descriptor)
    os.fsync(descriptor)


def validate_observation(value, runner=False):
    if value.get("schema") != 1 or value.get("privateAbiBytes") != 40 or value.get("numericSignalsUsed") is not False or value.get("reparent") != "Unrun" or value.get("cleanupConfirmed") is not True:
        raise RuntimeError("observation_schema_or_cleanup_failed")
    if value.get("outcome") != "Observed" or value.get("retainedChild") is not True:
        return False
    for key in ("self", "fork", "setsid", "exec"):
        sample = value[key]
        if sample["outcome"] != "Observed" or sample["bytes"] != 40 or any(type(sample[field]) is not int for field in ("pid", "sid", "resource", "jetsam")):
            return False
    if runner and (value["runner"]["outcome"] != "Observed" or value["runner"]["pid"] != os.getpid()):
        return False
    usage = value["resourceUsage"]
    if usage["invalidId"]["outcome"] != "Unknown" or usage["invalidId"]["active"] is not None or usage["missingSymbol"]["outcome"] != "Unsupported" or usage["missingSymbol"]["active"] is not None:
        raise RuntimeError("usage_error_was_normalized_to_zero")
    owner = value["self"]
    if any(owner[field] <= 0 for field in ("pid", "sid", "resource", "jetsam")):
        return False
    child = value["fork"]["pid"]
    if child <= 0 or child == owner["pid"]:
        return False
    for key in ("fork", "setsid", "exec"):
        sample = value[key]
        if sample["pid"] != child or any(sample[field] != owner[field] for field in ("resource", "jetsam")):
            return False
    if value["fork"]["sid"] != owner["sid"] or any(value[key]["sid"] != child for key in ("setsid", "exec")):
        return False
    for phase in ("before", "fork", "setsid", "exec", "afterWait"):
        sample = usage[phase]
        if sample["outcome"] != "Observed" or any(type(sample[field]) is not int for field in ("started", "exited", "active")):
            return False
        if sample["exited"] < 0 or sample["started"] < sample["exited"] or sample["active"] != sample["started"] - sample["exited"]:
            return False
    return True


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_receipt(root, name, report):
    temporary = root / "evidence.tmp"
    with temporary.open("w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(json.dumps(report, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, root / name)
    sync_directory(root)


def wait_controller_exit(profile, timeout=10, name="controller.lock"):
    descriptor = directory(Path(profile))
    locked = None
    try:
        # Open only the exact generation's pinned private file.
        locked = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
        metadata = os.fstat(locked)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1 or metadata.st_size != 0:
            raise RuntimeError("controller_lifetime_unconfirmed")
        reject_acl(locked)
        identity = (metadata.st_dev, metadata.st_ino)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != identity:
                    raise RuntimeError("controller_lifetime_identity_changed")
                return locked
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("controller_exit_unconfirmed")
                time.sleep(0.01)
    except BaseException:
        if locked is not None:
            os.close(locked)
        raise
    finally:
        os.close(descriptor)


def cleanup_all(jobs, cleanup):
    failures = []
    for job in reversed(jobs):
        if not job.get("cleanupConfirmed"):
            try:
                cleanup(job)
            except BaseException as error:
                failures.append({"label": job["label"], "failureType": type(error).__name__})
    return failures


def fixed_job(root, binary, domain_name, suffix, experiment="baseline"):
    if domain_name not in {"gui-aqua", "user-background"} or suffix not in {"a", "b"}:
        raise RuntimeError("invalid_fixed_job")
    session = "Aqua" if domain_name == "gui-aqua" else "Background"
    domain = ("gui/" if session == "Aqua" else "user/") + str(os.geteuid())
    label = "dev.lomi.coalition." + root.name.replace("-", "") + "." + domain_name + "." + suffix
    profile = root / "profiles" / (domain_name + "-" + suffix)
    state = profile / "result.json"
    definition = {"Label": label, "ProgramArguments": [str(binary), "--job", str(state)],
                  "RunAtLoad": False, "KeepAlive": False, "ExitTimeOut": 8,
                  "LimitLoadToSessionType": session, "Umask": 0o077,
                  "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"}
    if experiment == "admission":
        definition.update(LaunchOnlyOnce=suffix == "a", ThrottleInterval=1)
    elif experiment == "reparent":
        definition.update(LaunchOnlyOnce=True)
    elif experiment != "baseline":
        raise RuntimeError("unknown_experiment")
    return {"label": label, "domain": domain, "sessionType": session, "target": domain + "/" + label,
            "fileName": label + ".plist", "plist": str(Path.home() / "Library/LaunchAgents" / (label + ".plist")),
            "profile": str(profile), "state": str(state)}, plistlib.dumps(definition, sort_keys=True)


def validate_recovery_jobs(report, root, binary):
    allowed = {}
    experiment = report.get("experiment", "baseline")
    if experiment not in {"baseline", "admission", "reparent"}:
        raise RuntimeError("unknown_recovery_experiment")
    for domain in ("gui-aqua", "user-background"):
        for suffix in ("a", "b"):
            job, content = fixed_job(root, binary, domain, suffix, experiment)
            allowed[job["label"]] = (job, content)
    expected = {}
    for job in report["jobs"]:
        if job["label"] in expected or job["label"] not in allowed:
            raise RuntimeError("recovery_job_not_allowed")
        fixed, content = allowed[job["label"]]
        if any(job.get(key) != value for key, value in fixed.items()) or ((job.get("registrationIntent") or "plistSha256" in job) and job.get("plistSha256") != hashlib.sha256(content).hexdigest()):
            raise RuntimeError("recovery_job_identity_changed")
        extras = job.get("controllerExit", {}).get("extraProofs", {})
        if extras:
            import admission
            if experiment != "admission" or any(not admission.allowed_extra(name) or not isinstance(value.get("sha256"), str) or len(value["sha256"]) != 64 for name, value in extras.items()):
                raise RuntimeError("invalid_extra_proof_checkpoint")
        expected[job["label"]] = content
    return expected


def validate_frozen_root(root):
    if root.parent != BASE or root.name != str(uuid.UUID(root.name)):
        raise RuntimeError("frozen_run_identity_invalid")
    descriptor = directory(root)
    try:
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o700 or read_private(descriptor, ".fixture-marker") != root.name.encode():
            raise RuntimeError("private_run_marker_invalid")
        manifest_bytes = read_private(descriptor, "source-manifest.json", limit=1048576)
    finally:
        os.close(descriptor)
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") != 1 or not isinstance(manifest.get("files"), dict):
        raise RuntimeError("unsupported_source_manifest")
    source = root / "source"
    source_fd = directory(source)
    os.close(source_fd)
    for name, digest in manifest["files"].items():
        path = Path(name)
        if path.is_absolute() or any(part in {".", ".."} for part in path.parts) or not isinstance(digest, str) or len(digest) != 64:
            raise RuntimeError("invalid_source_manifest_entry")
        parent = directory((source / path).parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o400 or metadata.st_nlink != 1:
                    raise RuntimeError("unsafe_frozen_source")
                reject_acl(stream.fileno())
                if hashlib.sha256(stream.read()).hexdigest() != digest:
                    raise RuntimeError("frozen_source_changed")
        finally:
            os.close(parent)
    if not {"run_native.py", "owned_process.py", "probe.c"}.issubset(manifest["files"]):
        raise RuntimeError("incomplete_source_manifest")
    return manifest["files"]


def native(frozen_root=None, recovering=False, fixture_pause=None, experiment="baseline"):
    initialize_process_ownership()
    if sys.platform != "darwin":
        raise RuntimeError("native_macos_required")
    if frozen_root is None:
        BASE.mkdir(mode=0o700, exist_ok=True)
        base_metadata = BASE.lstat()
        if not stat.S_ISDIR(base_metadata.st_mode) or base_metadata.st_uid != os.geteuid() or stat.S_IMODE(base_metadata.st_mode) != 0o700:
            raise RuntimeError("private_artifact_root_required")
        root = BASE / str(uuid.uuid4())
        root.mkdir(mode=0o700)
        (root / ".fixture-marker").write_text(root.name)
        (root / ".fixture-marker").chmod(0o600)
        source = root / "source"
        shutil.copytree(Path(__file__).parent, source, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copyfile(REPOSITORY / "tools/owned_process.py", source / "owned_process.py")
        source_hashes = {str(path.relative_to(source)): sha(path) for path in source.rglob("*") if path.is_file()}
        (root / "source-manifest.json").write_text(json.dumps({"schema": 1, "files": source_hashes}, sort_keys=True))
        (root / "source-manifest.json").chmod(0o600)
        for path in source.rglob("*"):
            if path.is_file():
                path.chmod(0o400)
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
        for path in sorted((path for path in source.rglob("*") if path.is_dir()), key=lambda path: len(path.parts), reverse=True):
            sync_directory(path)
        sync_directory(source)
        for path in (root / ".fixture-marker", root / "source-manifest.json"):
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
        sync_directory(root)
        sync_directory(BASE)
        sync_directory(BASE.parent)
        validate_frozen_root(root)
        arguments = [sys.executable, "-B", str(source / "run_native.py"), "--run-native", "--frozen-root", str(root)]
        arguments += ["--experiment", experiment]
        if fixture_pause:
            arguments += ["--fixture-pause", fixture_pause]
        os.execv(sys.executable, arguments)
    root = Path(frozen_root).resolve()
    if root.parent != BASE or root.name != str(uuid.UUID(root.name)) or Path(__file__).resolve() != root / "source/run_native.py" or (root / ".fixture-marker").read_text() != root.name:
        raise RuntimeError("frozen_run_identity_invalid")
    source = root / "source"
    source_hashes = validate_frozen_root(root)
    source_manifest_hash = sha(root / "source-manifest.json")
    run_lock = os.open(root / "run.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    lock_metadata = os.fstat(run_lock)
    if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_uid != os.geteuid() or stat.S_IMODE(lock_metadata.st_mode) != 0o600 or lock_metadata.st_nlink != 1:
        os.close(run_lock)
        raise RuntimeError("unsafe_run_lock")
    try:
        fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(run_lock)
        raise RuntimeError("run_is_active")
    if any(sha(source / name) != digest for name, digest in source_hashes.items()):
        raise RuntimeError("frozen_inputs_changed")
    report = {"runId": root.name, "driverPid": os.getpid(), "experiment": experiment, "passed": False, "cleanupConfirmed": False,
              "experimentalPrivateAbi": True, "qualifiedProduct": False, "qualifiedHeadless": False,
              "pinnedSourceMatchesRunningKernel": "not established",
              "unqualified": ["closed external admission", "LaunchOnlyOnce", "arbitrary descendants", "arbitrary reparented workloads", "kill/empty fork-drain", "actual headless login", "release support", "macOS P1 closure"],
              "sourceManifestSha256": source_manifest_hash, "frozenDriverExecuted": True,
              "sourceHashes": source_hashes, "operations": [], "domains": {}, "jobs": []}
    agent_fd = None
    expected = {}
    binary = root / "probe"
    if recovering:
        receipt = root / ("recovery.json" if (root / "recovery.json").exists() else "evidence.json")
        descriptor = directory(root)
        try:
            report = json.loads(read_private(descriptor, receipt.name, limit=4194304))
        finally:
            os.close(descriptor)
        if report.get("runId") != root.name or report.get("sourceManifestSha256") != source_manifest_hash or report.get("sourceHashes") != source_hashes or sha(binary) != report.get("binarySha256"):
            raise RuntimeError("recovery_provenance_invalid")
        expected = validate_recovery_jobs(report, root, binary)
        experiment = report.get("experiment", "baseline")
        for job in report["jobs"]:
            job["cleanupConfirmed"] = False  # Re-audit exact resources, never inherit stale absence.
        report["recovery"] = True
        report["recoveryConfirmed"] = False
    checks_passed = False
    previous_term = signal.getsignal(signal.SIGTERM)

    def interrupted(signum, _frame):
        report["interruptedSignal"] = signum
        raise KeyboardInterrupt("fixture interrupted")

    signal.signal(signal.SIGTERM, interrupted)

    def save():
        durable_receipt(root, "recovery.json" if recovering else "evidence.json", report)

    def pause(phase):
        if not recovering and fixture_pause == phase and not report.get("fixturePause"):
            report["fixturePause"] = phase
            save()
            time.sleep(3)  # Explicit bounded fault-test hook; no extra admission.

    def command(name, argv, timeout=10, manager=False):
        operation = {"id": name, "command": [str(arg) for arg in argv], "exitCode": None}
        report["operations"].append(operation)
        save()
        result = run_owned(operation["command"], env=ENV, timeout=timeout)
        operation["exitCode"] = result.returncode
        if manager:
            if len(result.stdout) > 32768 or len(result.stderr) > 32768:
                raise RuntimeError("manager_output_limit")
            # launchctl can print inherited environment. Never retain it.
        else:
            prefix = root / (str(len(report["operations"])) + "-" + name)
            stdout = prefix.with_suffix(".stdout.log")
            stderr = prefix.with_suffix(".stderr.log")
            stdout.write_text(result.stdout)
            stderr.write_text(result.stderr)
            operation.update({"stdoutSha256": sha(stdout), "stderrSha256": sha(stderr)})
        save()
        return result

    def overrides(domain, label):
        result = command("exact-label-override", ["/bin/launchctl", "print-disabled", domain], manager=True)
        if result.returncode:
            raise RuntimeError("domain_override_query_failed")
        prefix = '"' + label + '" => '
        values = [line.strip()[len(prefix):] for line in result.stdout.splitlines() if line.strip().startswith(prefix)]
        if len(values) > 1 or any(value not in {"enabled", "disabled"} for value in values):
            raise RuntimeError("ambiguous_override")
        return values[0] if values else None

    def observe(job):
        result = command("exact-job-observation", ["/bin/launchctl", "print", job["target"]], manager=True)
        if result.returncode == 113:
            return None
        if result.returncode:
            raise RuntimeError("job_observation_failed")
        lines = result.stdout.splitlines()
        if not lines or lines[0] != job["target"] + " = {":
            raise RuntimeError("job_identity_changed")
        for key, wanted in [("path", job["plist"]), ("program", str(binary))]:
            values = [line[len('\t' + key + ' = '):] for line in lines if line.startswith('\t' + key + ' = ')]
            if values != [wanted]:
                raise RuntimeError("job_identity_changed")
        starts = [index for index, line in enumerate(lines) if line == "\targuments = {"]
        if len(starts) != 1 or lines[starts[0]+1:starts[0]+5] != ["\t\t" + str(binary), "\t\t--job", "\t\t" + job["state"], "\t}"]:
            raise RuntimeError("job_arguments_changed")
        pids = [line.removeprefix("\tpid = ") for line in lines if line.startswith("\tpid = ")]
        if not pids:
            return {"pid": None}
        if len(pids) != 1 or not pids[0].isdigit() or not 0 < int(pids[0]) <= 0x7fffffff:
            raise RuntimeError("job_pid_ambiguous")
        return {"pid": int(pids[0])}

    def state_value(job):
        descriptor = directory(Path(job["profile"]))
        try:
            encoded = read_private(descriptor, "result.json")
        finally:
            os.close(descriptor)
        if not encoded:
            return None
        try:
            return json.loads(encoded)
        except json.JSONDecodeError:
            return None  # The exclusive new file may still be being flushed.

    def cleanup_job(job):
        if not job.get("registrationIntent"):
            # We created only this fresh private empty directory before auditing
            # external names. Never act on an unauthenticated manager resource.
            if Path(job["profile"]).exists():
                Path(job["profile"]).rmdir()
            job["cleanupConfirmed"] = True
            return
        current = observe(job)
        if current is not None:
            result = command("bootout-exact-owned-job", ["/bin/launchctl", "bootout", job["target"]], manager=True)
            if result.returncode and observe(job) is not None:
                raise RuntimeError("bootout_uncertain")
        deadline = time.monotonic() + 10
        while observe(job) is not None:
            if time.monotonic() >= deadline:
                raise RuntimeError("job_removal_uncertain")
            time.sleep(0.025)
        profile = Path(job["profile"])
        checkpoint = job.get("controllerExit")
        if job.get("kickstartIntent") and checkpoint is None:
            observation = state_value(job)
            if observation is None or observation.get("cleanupConfirmed") is not True:
                raise RuntimeError("owned_child_wait_unconfirmed")
            lifetime = wait_controller_exit(profile)
            try:
                metadata = os.fstat(lifetime)
                descriptor = directory(profile)
                try:
                    content = read_private(descriptor, "result.json")
                finally:
                    os.close(descriptor)
                completed_checkpoint = {"lockDevice": metadata.st_dev, "lockInode": metadata.st_ino,
                                        "resultSha256": hashlib.sha256(content).hexdigest()}
                if experiment == "admission":
                    import admission
                    completed_checkpoint["extraProofs"] = admission.capture_proofs({"directory": directory, "read_private": read_private, "wait_lifetime": wait_controller_exit}, profile)
                job["controllerExit"] = completed_checkpoint
                save()  # Durable true-exit checkpoint BEFORE deleting any proof.
                pause("exit-checkpoint")
            finally:
                os.close(lifetime)
        elif checkpoint is not None and profile.exists():
            descriptor = directory(profile)
            try:
                content = read_private(descriptor, "result.json")
                if content is not None and hashlib.sha256(content).hexdigest() != checkpoint["resultSha256"]:
                    raise RuntimeError("exit_checkpoint_result_changed")
                lock = read_private(descriptor, "controller.lock")
                if lock is not None:
                    metadata = os.stat("controller.lock", dir_fd=descriptor, follow_symlinks=False)
                    if [metadata.st_dev, metadata.st_ino] != [checkpoint["lockDevice"], checkpoint["lockInode"]]:
                        raise RuntimeError("exit_checkpoint_lock_changed")
                    lifetime = wait_controller_exit(profile)
                    os.close(lifetime)
            finally:
                os.close(descriptor)
        extras = job.get("controllerExit", {}).get("extraProofs", {})
        if profile.exists() and extras:
            descriptor = directory(profile)
            try:
                for name, proof in extras.items():
                    content = read_private(descriptor, name)
                    if content is not None:
                        if hashlib.sha256(content).hexdigest() != proof["sha256"]:
                            raise RuntimeError("extra_proof_changed")
                        if name.endswith(".lock"):
                            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                            if [metadata.st_dev, metadata.st_ino] != [proof["device"], proof["inode"]]:
                                raise RuntimeError("extra_lifetime_changed")
                            fd = wait_controller_exit(profile, name=name)
                            os.close(fd)
            finally:
                os.close(descriptor)
        # Reaffirm durability even on a retry after a post-rename fsync error.
        # An in-memory/existing checkpoint alone is not a durability barrier.
        save()
        current_file = read_private(agent_fd, job["fileName"])
        if current_file is not None:
            remove_exact(agent_fd, job["fileName"], expected[job["label"]])
        job["overrideAfter"] = overrides(job["domain"], job["label"])
        if job["overrideAfter"] != job["overrideBefore"] or read_private(agent_fd, job["fileName"]) is not None:
            raise RuntimeError("registration_audit_failed")
        state_directory = Path(job["profile"])
        if not state_directory.exists():
            if job.get("kickstartIntent") and not job.get("controllerExit"):
                raise RuntimeError("missing_exit_checkpoint")
            job["cleanupConfirmed"] = True
            job["after"] = {"job": "absent", "plist": "absent", "profile": "absent", "override": job["overrideAfter"]}
            save()
            return
        descriptor = directory(state_directory)
        try:
            if set(os.listdir(descriptor)) - {"result.json", "controller.lock"} - set(extras):
                raise RuntimeError("unknown_profile_entries")
            if extras:
                archive = root / "extra-proofs" / job["label"]
                archive.mkdir(parents=True, mode=0o700, exist_ok=True)
                for name, proof in extras.items():
                    content = read_private(descriptor, name)
                    if content is not None:
                        if hashlib.sha256(content).hexdigest() != proof["sha256"]:
                            raise RuntimeError("extra_proof_changed")
                        target = archive / name
                        if target.exists() and target.read_bytes() != content:
                            raise RuntimeError("archived_extra_proof_changed")
                        if not target.exists():
                            with target.open("xb") as stream:
                                os.fchmod(stream.fileno(), 0o600)
                                stream.write(content)
                                stream.flush()
                                os.fsync(stream.fileno())
                        sync_directory(archive)
                        sync_directory(archive.parent)
                        sync_directory(root)
                        remove_exact(descriptor, name, content)
            lock_content = read_private(descriptor, "controller.lock")
            if lock_content is not None:
                remove_exact(descriptor, "controller.lock", lock_content)
            content = read_private(descriptor, "result.json")
            if content is not None:
                (root / (job["label"] + ".observation.json")).write_bytes(content)
                remove_exact(descriptor, "result.json", content)
        finally:
            os.close(descriptor)
        state_directory.rmdir()
        job["after"] = {"job": "absent", "plist": "absent", "profile": "absent", "override": job["overrideAfter"]}
        job["cleanupConfirmed"] = True
        save()

    save()
    try:
        if recovering:
            agent_fd = directory(Path.home() / "Library/LaunchAgents")
            # All identities were validated together before any manager mutation.
            failures = cleanup_all(report["jobs"], cleanup_job)
            report["recoveryFailures"] = failures
            report["recoveryConfirmed"] = not failures and all(job.get("cleanupConfirmed") for job in report["jobs"])
            return report["recoveryConfirmed"]
        pinned = json.loads((source / "upstream/manifest.json").read_text())
        if any(sha(source / "upstream" / name) != value["sha256"] for name, value in pinned["files"].items()):
            raise RuntimeError("pinned_upstream_hash_mismatch")
        report["upstream"] = pinned
        with tarfile.open(root / "source.tar.gz", "w:gz") as archive:
            archive.add(source, arcname="source")
        with (root / "source.tar.gz").open("rb") as stream:
            os.fsync(stream.fileno())
        report["sourceArchiveSha256"] = sha(root / "source.tar.gz")
        sdk_result = command("sdk", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"])
        compiler_result = command("compiler", ["/usr/bin/xcrun", "--sdk", "macosx", "--find", "clang"])
        if sdk_result.returncode or compiler_result.returncode:
            raise RuntimeError("compile_tools_unavailable")
        sdk = Path(sdk_result.stdout.strip())
        compiler = Path(compiler_result.stdout.strip())
        version = command("compiler-version", [compiler, "--version"])
        system = command("macos-version", ["/usr/bin/sw_vers"])
        if version.returncode or system.returncode:
            raise RuntimeError("tool_version_failed")
        manual = Path("/usr/share/man/man5/launchd.plist.5")
        if experiment == "admission":
            shutil.copyfile(manual, root / "launchd.plist.5")
            report["launchdManualSha256"] = sha(root / "launchd.plist.5")
        report["platform"] = {"macos": system.stdout, "kernel": os.uname().release, "machine": os.uname().machine,
                              "sdk": str(sdk), "sdkSettingsSha256": sha(sdk / "SDKSettings.json"),
                              "compiler": str(compiler), "compilerSha256": sha(compiler)}
        compiled = command("build", [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-g0", "-isysroot", sdk, source / {"baseline": "probe.c", "admission": "admission_probe.c", "reparent": "reparent_probe.c"}[experiment], "-lbsm", "-o", binary], timeout=30)
        if compiled.returncode:
            raise RuntimeError("compile_failed")
        binary.chmod(0o500)
        with binary.open("rb") as stream:
            os.fsync(stream.fileno())
        report["binarySha256"] = sha(binary)
        direct = command("known-runner-and-child", [binary, "--runner", str(os.getpid())])
        if direct.returncode:
            raise RuntimeError("direct_fixture_failed")
        value = json.loads(direct.stdout)
        report["direct"] = value
        if not validate_observation(value, runner=True):
            raise RuntimeError("direct_query_unknown_or_unsupported")
        parent_coalitions = (value["runner"]["resource"], value["runner"]["jetsam"])
        agent_directory = Path.home() / "Library/LaunchAgents"
        agent_fd = directory(agent_directory)
        (root / "profiles").mkdir(mode=0o700)
        if experiment == "admission":
            import admission
            api = dict(globals())
            api.update(locals())
            api["wait_lifetime"] = wait_controller_exit
            checks_passed = admission.run(api)
            return checks_passed
        for domain_name, domain, session_type in [("gui-aqua", "gui/" + str(os.geteuid()), "Aqua"), ("user-background", "user/" + str(os.geteuid()), "Background")]:
            result = {"domain": domain, "sessionType": session_type, "outcome": "Unknown", "headlessLoginTested": False}
            report["domains"][domain_name] = result
            group = []
            try:
                for suffix in ("a", "b"):
                    job, content = fixed_job(root, binary, domain_name, suffix, experiment)
                    label = job["label"]
                    profile = Path(job["profile"])
                    profile.mkdir(mode=0o700)
                    sync_directory(profile.parent)
                    name = job["fileName"]
                    job["cleanupConfirmed"] = False
                    report["jobs"].append(job)
                    group.append(job)
                    expected[label] = content
                    job["overrideBefore"] = overrides(domain, label)
                    if job["overrideBefore"] is not None or observe(job) is not None or read_private(agent_fd, name) is not None:
                        raise RuntimeError("fresh_owned_registration_required")
                    job["before"] = {"job": "absent", "plist": "absent", "profile": "new-empty", "override": None}
                    job["registrationIntent"] = True
                    job["plistSha256"] = hashlib.sha256(content).hexdigest()
                    save()
                    publish(agent_fd, name, content)
                    job["bootstrapIntent"] = True
                    save()
                    bootstrapped = command("bootstrap-exact-job", ["/bin/launchctl", "bootstrap", domain, job["plist"]], manager=True)
                    if bootstrapped.returncode:
                        result["bootstrapExit"] = bootstrapped.returncode
                        raise RuntimeError("domain_bootstrap_failed")
                for job in group:
                    job["kickstartIntent"] = True
                    save()
                    started = command("kickstart-exact-job", ["/bin/launchctl", "kickstart", job["target"]], manager=True)
                    if started.returncode:
                        raise RuntimeError("domain_kickstart_failed")
                deadline = time.monotonic() + 3
                for job in group:
                    while True:
                        observation = state_value(job)
                        if observation is not None:
                            break
                        if time.monotonic() >= deadline:
                            raise RuntimeError("job_observation_timeout")
                        time.sleep(0.01)
                    if experiment == "reparent":
                        import reparent
                        valid = reparent.validate(observation, failure_case=job["label"].endswith(".b"))
                    else:
                        valid = validate_observation(observation)
                    if not valid:
                        raise RuntimeError("job_query_unknown_or_unsupported")
                    live = observe(job)
                    if not live or live["pid"] != observation["self"]["pid"]:
                        raise RuntimeError("manager_pid_mismatch")
                    job["observation"] = observation
                pause("results")
                pair = [(job["observation"]["self"]["resource"], job["observation"]["self"]["jetsam"]) for job in group]
                result["distinctNonzeroResource"] = all(values[0] for values in pair) and pair[0][0] != pair[1][0]
                result["distinctNonzeroJetsam"] = all(values[1] for values in pair) and pair[0][1] != pair[1][1]
                result["disjointFromRunner"] = all(values[0] != parent_coalitions[0] and values[1] != parent_coalitions[1] for values in pair)
                if experiment == "reparent":
                    result["counterTraces"] = [{phase: job["observation"]["usage"][phase]["active"] for phase in ("initial", "together", "orphan", "final")} for job in group]
                    result["counterTraceMatches"] = True  # Each exact scenario validated above.
                    result["reparentOrder"] = "fork-setsid-exec-register-reparent-no-further-exec"
                else:
                    result["counterTraces"] = [[job["observation"]["resourceUsage"][phase]["active"] for phase in ("before", "fork", "setsid", "exec", "afterWait")] for job in group]
                    result["counterTraceMatches"] = all(trace == [1, 2, 2, 2, 1] for trace in result["counterTraces"])
                result["outcome"] = "Observed" if all(result[key] for key in ("distinctNonzeroResource", "distinctNonzeroJetsam", "disjointFromRunner", "counterTraceMatches")) else "Unknown"
            except Exception as error:
                result["failureType"] = type(error).__name__
            finally:
                failures = cleanup_all(group, cleanup_job)
                if failures:
                    report.setdefault("cleanupFailures", []).extend(failures)
                    raise RuntimeError("exact_resource_cleanup_uncertain")
                save()
        checks_passed = all(value["outcome"] == "Observed" for value in report["domains"].values())
    except BaseException as error:
        report["failureType"] = type(error).__name__
        raise
    finally:
        # A repeated TERM must not interrupt the bounded exact-resource cleanup.
        # SIGKILL cannot be handled; retain this artifact journal for recovery.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            if agent_fd is not None:
                failures = cleanup_all(report["jobs"], cleanup_job)
                os.close(agent_fd)
                if failures:
                    report.setdefault("cleanupFailures", []).extend(failures)
                    raise RuntimeError("exact_resource_cleanup_uncertain")
            if sha(root / "source-manifest.json") != source_manifest_hash or any(sha(source / name) != digest for name, digest in source_hashes.items()) or (binary.exists() and report.get("binarySha256") and sha(binary) != report["binarySha256"]):
                raise RuntimeError("frozen_inputs_changed")
            report["cleanupConfirmed"] = report.get("direct", {}).get("cleanupConfirmed", False) and all(job.get("cleanupConfirmed") for job in report["jobs"])
            if not recovering:
                report["passed"] = checks_passed and report["cleanupConfirmed"]
        finally:
            save()
            print(root / ("recovery.json" if recovering else "evidence.json"))
            signal.signal(signal.SIGTERM, previous_term)
            os.close(run_lock)
    return report["passed"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true")
    parser.add_argument("--frozen-root", help=argparse.SUPPRESS)
    parser.add_argument("--recover", metavar="UUID", help="recover only one validated frozen UUID run")
    parser.add_argument("--experiment", choices=("baseline", "admission", "reparent"), default="baseline")
    parser.add_argument("--fixture-pause", choices=("results", "exit-checkpoint"), help=argparse.SUPPRESS)
    options = parser.parse_args()
    if not options.run_native:
        parser.error("--run-native is required")
    if options.recover:
        root = BASE / str(uuid.UUID(options.recover))
        validate_frozen_root(root)
        if Path(__file__).resolve() != root / "source/run_native.py":
            os.execv(sys.executable, [sys.executable, "-B", str(root / "source/run_native.py"), "--run-native", "--frozen-root", str(root), "--recover", root.name])
        if options.frozen_root != str(root):
            parser.error("recovery root mismatch")
    sys.exit(0 if native(options.frozen_root, recovering=bool(options.recover), fixture_pause=options.fixture_pause, experiment=options.experiment) else 1)
