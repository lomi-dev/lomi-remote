"""Unstaged root launcher prototype. Production constants fail closed here."""
import hashlib
import json
import os
import re
import stat
import sys

MAX_ADMISSION_BYTES = 4096
MAX_FREEZE_BYTES = 1024 * 1024
MAX_CONTROLLER_BYTES = 8 * 1024 * 1024
SCOPE = "private-positive-auth-eleven-only"
ADMISSION_KEYS = {"schemaVersion", "scope", "freezeSha256", "rootReviewed", "controllerSha256",
                  "launcherSha256"}

# Fixed staging contract. This closure is not installed, and the digest remains
# deliberately invalid until an independently reviewed freeze is installed.
TRUSTED_ROOT = "/Library/PrivilegedHelperTools/Lomi/private-positive-eleven"
ADMISSION_NAME = "admission.json"
RUN_ADMISSION_NAME = "run-admission.json"
FREEZE_NAME = "freeze.json"
CONTROLLER_NAME = "controller.py"
LAUNCHER_NAME = "launcher.py"
ROOT_UID = 0
PINNED_PYTHON = "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
NATIVE_ADMISSION_ROOT = "/private/var/db/lomi/consumer-private-eleven-root-admission"


class Rejected(RuntimeError):
    pass


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _trusted_root_fd(root_path, uid, base_path="/"):
    if not os.path.isabs(root_path) or not os.path.isabs(base_path):
        raise Rejected("trusted root must be absolute")
    if os.path.commonpath((base_path, root_path)) != base_path:
        raise Rejected("trusted root escapes traversal base")
    fd = os.open(base_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            raise Rejected("trusted root base metadata rejected")
        relative = os.path.relpath(root_path, base_path)
        components = [] if relative == "." else relative.split(os.sep)
        for component in components:
            if not component or component in (".", ".."):
                raise Rejected("invalid trusted root path")
            try:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=fd)
            except OSError as exc:
                raise Rejected("trusted root traversal rejected") from exc
            info = os.fstat(next_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
                os.close(next_fd)
                raise Rejected("trusted root ancestor metadata rejected")
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


def _read_at(root_fd, name, *, uid, max_bytes):
    if "/" in name or name in ("", ".", ".."):
        raise Rejected("invalid trusted filename")
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
    except OSError as exc:
        raise Rejected("trusted input unavailable") from exc
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1 or
                before.st_mode & 0o222):
            raise Rejected("trusted input metadata rejected")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise Rejected("trusted input exceeds size limit")
            chunks.append(chunk)
        after = os.fstat(fd)
        identity = lambda x: (x.st_dev, x.st_ino, x.st_uid, x.st_mode, x.st_nlink, x.st_size)
        if identity(before) != identity(after) or total != after.st_size:
            raise Rejected("trusted input changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _admit_from_fd(root_fd, uid):
    raw_admission = _read_at(root_fd, ADMISSION_NAME, uid=uid, max_bytes=MAX_ADMISSION_BYTES)
    try:
        admission = json.loads(raw_admission.decode("ascii"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError) as exc:
        raise Rejected("invalid admission document") from exc
    if (not isinstance(admission, dict) or set(admission) != ADMISSION_KEYS or
            type(admission.get("schemaVersion")) is not int or admission["schemaVersion"] != 1 or
            admission.get("scope") != SCOPE or admission.get("rootReviewed") is not True or
            not _digest(admission.get("freezeSha256")) or not _digest(admission.get("controllerSha256")) or
            not _digest(admission.get("launcherSha256"))):
        raise Rejected("admission rejected")
    launcher = _read_at(root_fd, LAUNCHER_NAME, uid=uid, max_bytes=MAX_ADMISSION_BYTES * 4)
    if hashlib.sha256(launcher).hexdigest() != admission["launcherSha256"]:
        raise Rejected("launcher digest mismatch")
    raw_freeze = _read_at(root_fd, FREEZE_NAME, uid=uid, max_bytes=MAX_FREEZE_BYTES)
    try:
        freeze = json.loads(raw_freeze.decode("ascii"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError) as exc:
        raise Rejected("invalid freeze document") from exc
    freeze_sha = hashlib.sha256(raw_freeze).hexdigest()
    if (freeze_sha != admission["freezeSha256"] or not isinstance(freeze, dict) or
            not isinstance(freeze.get("sourceSha256"), dict) or
            freeze["sourceSha256"].get("controller.py") != admission["controllerSha256"]):
        raise Rejected("admission/freeze binding rejected")
    source = _read_at(root_fd, CONTROLLER_NAME, uid=uid, max_bytes=MAX_CONTROLLER_BYTES)
    if hashlib.sha256(source).hexdigest() != admission["controllerSha256"]:
        raise Rejected("controller digest mismatch")
    return source, admission


def admit_from_root(*, root_path, uid, base_path="/"):
    """Test seam: safely admit bytes beneath an injected trusted root."""
    root_fd = _trusted_root_fd(root_path, uid, base_path)
    try:
        source, _ = _admit_from_fd(root_fd, uid)
        return source
    finally:
        os.close(root_fd)


def _valid_run_admission(root_fd, uid, source_sha, freeze_sha):
    raw = _read_at(root_fd, RUN_ADMISSION_NAME, uid=uid, max_bytes=MAX_ADMISSION_BYTES)
    try:
        obj = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError) as exc:
        raise Rejected("invalid run admission") from exc
    keys = {"schemaVersion", "scope", "freezeSha256", "rootReviewed", "controllerSha256",
            "executeController", "nativeAdmissionPath"}
    if not (isinstance(obj, dict) and set(obj) == keys and type(obj.get("schemaVersion")) is int and
            obj["schemaVersion"] == 1 and obj.get("scope") == SCOPE and obj.get("rootReviewed") is True and
            obj.get("freezeSha256") == freeze_sha and obj.get("controllerSha256") == source_sha and
            obj.get("executeController") is True):
        return None
    path = obj.get("nativeAdmissionPath")
    prefix = NATIVE_ADMISSION_ROOT + "/"
    if (not isinstance(path, str) or not path.startswith(prefix) or
            re.fullmatch(re.escape(prefix) + r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/native-admission\.json", path) is None or
            os.path.normpath(path) != path):
        return None
    return path


def _run_from_fd(root_fd, uid):
    source, admission = _admit_from_fd(root_fd, uid)
    try:
        native_admission_path = _valid_run_admission(root_fd, uid, admission["controllerSha256"],
                                                     admission["freezeSha256"])
    except Rejected:
        native_admission_path = None
    if not native_admission_path:
        return "PREPARED_NOT_EXECUTED"
    prior_argv = sys.argv
    sys.argv = [os.path.join(TRUSTED_ROOT, CONTROLLER_NAME), "--native-admission", native_admission_path]
    try:
        execute_admitted(source, filename=os.path.join(TRUSTED_ROOT, CONTROLLER_NAME))
    finally:
        sys.argv = prior_argv
    return "EXECUTED"


def execute_admitted(source, *, filename="<root-reviewed-controller>", namespace=None):
    """Execute precisely the already admitted in-memory bytes."""
    if namespace is None:
        namespace = {"__name__": "__main__", "__file__": filename}
    exec(compile(source, filename, "exec", dont_inherit=True), namespace, namespace)
    return namespace


def main():
    if sys.argv[1:]:
        raise Rejected("launcher accepts no arguments")
    if (sys.executable != PINNED_PYTHON or not sys.flags.isolated or not sys.flags.no_site or
            not sys.dont_write_bytecode):
        raise Rejected("pinned isolated interpreter flags required")
    root_fd = _trusted_root_fd(TRUSTED_ROOT, ROOT_UID)
    try:
        return _run_from_fd(root_fd, ROOT_UID)
    finally:
        os.close(root_fd)


def _report_status(status):
    if status == "PREPARED_NOT_EXECUTED":
        # Fixed text only: the default root invocation has made no native call.
        print(status, flush=True)
    elif status != "EXECUTED":
        raise Rejected("unexpected launcher status")


if __name__ == "__main__":
    try:
        _report_status(main())
    except Rejected:
        raise SystemExit(126)
