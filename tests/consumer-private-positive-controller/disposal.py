"""Owned private PG-data disposal after retained cleanup; no process operations.

The trusted caller owns the exclusive private work tree. It must not call the
Guardian again after disposal. Deletion unlinks owned entries, not secure erase.
All paths stay below the original fd-bound data root; no symlink is followed.
"""
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import stat

MARKER = "lomi-private-data-owned.json"
MAX_ENTRIES = 32768
MAX_BYTES = 2*1024**3
MAX_DEPTH = 32


class Rejected(RuntimeError):
    def __init__(self):
        super().__init__("private data disposal rejected")


def identity(info, *, directory=False):
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or info.st_uid != os.getuid() or not directory and info.st_nlink != 1):
        raise Rejected()
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))


def open_directory(name, *, parent=None):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)


def read_marker(parent, name, expected_identity, expected):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    with os.fdopen(fd, "rb") as stream:
        if identity(os.fstat(stream.fileno())) != expected_identity or stream.read(2049) != expected:
            raise Rejected()


@dataclass(frozen=True, slots=True, repr=False)
class DataLease:
    owner: object
    work: Path
    work_identity: tuple
    data_identity: tuple
    marker_identity: tuple
    marker_bytes: bytes
    root_marker_identity: tuple
    root_marker_bytes: bytes
    run_id: str
    socket_identity: tuple
    ancestry: tuple

    def __repr__(self):
        return "<DataLease private>"


@dataclass(frozen=True, slots=True)
class DisposalResult:
    code: str
    disposed: bool
    removed_entries: int = 0


def acquire(owner):
    """Before any token, bind the original owned work/data inode and marker."""
    lease = None
    try:
        work = owner.work
        if (type(work) is not Path and not isinstance(work, Path)) or not work.is_absolute() or work.resolve() != work:
            raise Rejected()
        if any(path.is_symlink() for path in (work, *work.parents)):
            raise Rejected()
        if len(work.parents)>20:raise Rejected()
        ancestry=tuple((path, path.lstat().st_dev, path.lstat().st_ino) for path in work.parents)
        run_id = owner.run_id
        if (type(run_id) is not str
                or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", run_id) is None
                or owner.marker_path != work/"guardian-owned.json"):
            raise Rejected()
        expected = (json.dumps({"runId": run_id, "work": str(work), "data": str(work/"data"),
                                "socket": str(work/"socket")}, sort_keys=True)+"\n").encode()
        if owner.marker_bytes != expected:
            raise Rejected()
        work_fd = open_directory(work)
        try:
            work_identity = identity(os.fstat(work_fd), directory=True)
            socket_identity=identity(os.stat("socket",dir_fd=work_fd,follow_symlinks=False),directory=True)
            root_marker_identity = identity(os.stat("guardian-owned.json", dir_fd=work_fd, follow_symlinks=False))
            read_marker(work_fd, "guardian-owned.json", root_marker_identity, expected)
            data_fd = open_directory("data", parent=work_fd)
            try:
                data_identity = identity(os.fstat(data_fd), directory=True)
                if data_identity[0] != work_identity[0]:
                    raise Rejected()
                marker_bytes = (json.dumps({"runId": run_id, "workDevice": work_identity[0],
                    "workInode": work_identity[1], "dataDevice": data_identity[0],
                    "dataInode": data_identity[1], "uid": os.getuid()}, sort_keys=True)+"\n").encode()
                marker_fd = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                    0o600, dir_fd=data_fd)
                with os.fdopen(marker_fd, "wb") as stream:
                    stream.write(marker_bytes)
                    stream.flush()
                    marker_identity = identity(os.fstat(stream.fileno()))
                lease = DataLease(owner, work, work_identity, data_identity, marker_identity,
                                  marker_bytes, root_marker_identity, expected, run_id,socket_identity,ancestry)
                owner._private_disposal_attempted = False
            finally:
                os.close(data_fd)
        finally:
            os.close(work_fd)
    except BaseException:
        pass
    if lease is None:
        raise Rejected()
    return lease


def cleanup_proven(owner, lease, cleanup):
    if (type(lease) is not DataLease or lease.owner is not owner or owner.work != lease.work
            or owner.run_id != lease.run_id or owner.marker_bytes != lease.root_marker_bytes
            or owner._emergency_sink.closed is not True or owner.handlers_installed is not False
            or cleanup is not owner.cleanup_result or type(cleanup) is not dict
            or any(cleanup.get(name) is not True for name in
                   ("completed", "foregroundPostgresRegistered", "startupConfirmed", "postmasterNormalExit",
                    "pgCtlStatusAbsent", "postmasterPidAbsent", "socketDirectoryEmpty", "allRetainedChildrenReaped"))
            or cleanup.get("ownershipUnresolved") is not False or owner.postgres is None
            or owner.postgres.forced is not False or type(owner.postgres.exit_code) is not int
            or owner.postgres.exit_code != 0 or not owner.children
            or not any(record is owner.postgres for record in owner.children)
            or any(record.reaped is not True or record.group_quiet is not True for record in owner.children)):
        raise Rejected()
    utilities = [record for record in owner.children if record.name == "pg_ctl"]
    if (len(utilities) != 3 or [record.exit_code for record in utilities] != [0, 0, 3]
            or any(type(record.exit_code) is not int for record in utilities)
            or utilities[0].argv[1:] != ("-D", str(lease.work/"data"), "status")
            or utilities[1].argv[1:] != ("-D", str(lease.work/"data"), "-m", "immediate", "-w", "-t", "20", "stop")
            or utilities[2].argv[1:] != ("-D", str(lease.work/"data"), "status")):
        raise Rejected()


def check_time(owner):
    now = owner.clock()
    if (type(now) not in (int, float) or not math.isfinite(now)
            or type(owner.started) not in (int, float) or not math.isfinite(owner.started)
            or not owner.started <= now < owner.started+900
            or owner.qualification_deadline != owner.started+900
            or owner.emergency_deadline != owner.started+960):
        raise Rejected()


def inventory(fd, device, owner, budget, depth=0):
    check_time(owner)
    if depth > MAX_DEPTH:
        raise Rejected()
    nodes = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", entry.name) is None or entry.name in (".", ".."):
                raise Rejected()
            budget[0] += 1
            if budget[0] > MAX_ENTRIES:
                raise Rejected()
            info = entry.stat(follow_symlinks=False)
            directory = stat.S_ISDIR(info.st_mode)
            original = identity(info, directory=directory)
            if info.st_dev != device:
                raise Rejected()
            budget[1] += max(info.st_size, info.st_blocks*512) if not directory else 0
            if budget[1] > MAX_BYTES:
                raise Rejected()
            children = None
            if directory:
                child_fd = open_directory(entry.name, parent=fd)
                try:
                    if identity(os.fstat(child_fd), directory=True) != original:
                        raise Rejected()
                    children = inventory(child_fd, device, owner, budget, depth+1)
                finally:
                    os.close(child_fd)
            nodes.append((entry.name, original, children))
    return tuple(nodes)


def erase(fd, nodes, owner, removed):
    for name, original, children in nodes:
        check_time(owner)
        directory = children is not None
        if identity(os.stat(name, dir_fd=fd, follow_symlinks=False), directory=directory) != original:
            raise Rejected()
        if directory:
            child_fd = open_directory(name, parent=fd)
            try:
                if identity(os.fstat(child_fd), directory=True) != original:
                    raise Rejected()
                erase(child_fd, children, owner, removed)
            finally:
                os.close(child_fd)
            if identity(os.stat(name, dir_fd=fd, follow_symlinks=False), directory=True) != original:
                raise Rejected()
            os.rmdir(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)
        removed[0] += 1


def dispose(owner, lease, cleanup):
    """Fail closed, no raw exception/repr/traceback or PG file content returned.

    Preflight scans metadata only. The exclusive owner guarantees no writer
    remains. Partial deletion or any uncertainty stays unqualified; no retry
    blesses a new root and no further Guardian cleanup is permitted.
    """
    result = DisposalResult("private-data-disposal-rejected", False)
    try:
        if getattr(owner, "_private_disposal_attempted", None) is not False:
            raise Rejected()
        owner._private_disposal_attempted = True
        cleanup_proven(owner, lease, cleanup)
        check_time(owner)
        work = lease.work
        if (work.resolve() != work or any(p.is_symlink() for p in (work, *work.parents))
                or identity(work.lstat(), directory=True) != lease.work_identity
                or any((path.lstat().st_dev,path.lstat().st_ino)!=(device,inode)
                       for path,device,inode in lease.ancestry)):
            raise Rejected()
        work_fd = open_directory(work)
        try:
            if identity(os.fstat(work_fd), directory=True) != lease.work_identity:
                raise Rejected()
            read_marker(work_fd, "guardian-owned.json", lease.root_marker_identity, lease.root_marker_bytes)
            data_fd = open_directory("data", parent=work_fd)
            try:
                if identity(os.fstat(data_fd), directory=True) != lease.data_identity:
                    raise Rejected()
                read_marker(data_fd, MARKER, lease.marker_identity, lease.marker_bytes)
                try:
                    os.stat("postmaster.pid", dir_fd=data_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise Rejected()
                socket_fd = open_directory("socket", parent=work_fd)
                try:
                    if identity(os.fstat(socket_fd), directory=True)!=lease.socket_identity:raise Rejected()
                    with os.scandir(socket_fd) as entries:
                        if next(entries, None) is not None:
                            raise Rejected()
                finally:
                    os.close(socket_fd)
                nodes = inventory(data_fd, lease.data_identity[0], owner, [0, 0])
                removed = [0]
                erase(data_fd, nodes, owner, removed)
                with os.scandir(data_fd) as entries:
                    if next(entries, None) is not None:
                        raise Rejected()
                if identity(os.stat("data", dir_fd=work_fd, follow_symlinks=False), directory=True) != lease.data_identity:
                    raise Rejected()
                os.rmdir("data", dir_fd=work_fd)
                try:
                    os.stat("data", dir_fd=work_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise Rejected()
                if identity(work.lstat(),directory=True)!=lease.work_identity:raise Rejected()
                read_marker(work_fd,"guardian-owned.json",lease.root_marker_identity,lease.root_marker_bytes)
                result = DisposalResult("private-data-disposed", True, removed[0]+1)
            finally:
                os.close(data_fd)
        finally:
            os.close(work_fd)
    except BaseException:
        pass
    return result
