"""Exact AppArmor development prerequisite with recoverable per-run ownership."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

DEST = Path("/etc/apparmor.d/lomi-git-bwrap-experimental")
EXPECTED = "632d84dbcf93dd242838d3d5090e344fb9ba7c83e3ee935d06f4e055479d7b86"
STAGE_PREFIX = "/etc/apparmor.d/.lomi-git-bwrap-experimental-"
PROFILE_NAME = "lomi-git-bwrap-experimental"


def checked_profile(path):
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
    assert metadata.st_mode & 0o6022 == 0
    assert hashlib.sha256(path.read_bytes()).hexdigest() == EXPECTED
    return metadata


def owned_stage(path):
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
    assert metadata.st_mode & 0o6022 == 0
    return metadata


def main():
    assert os.getuid() != 0
    action, token = sys.argv[1:]
    assert action in ("inspect", "prepare", "cleanup")
    assert re.fullmatch(r"[0-9a-f]{32}", token)
    stage = Path(STAGE_PREFIX + token)
    source = Path(__file__).with_name("bwrap.apparmor")
    assert hashlib.sha256(source.read_bytes()).hexdigest() == EXPECTED
    existed = os.path.lexists(DEST)
    if existed:
        checked_profile(DEST)
    report = {"initiallyAbsent": not existed, "profilePath": str(DEST),
              "stagePath": str(stage), "sha256": EXPECTED,
              "action": action, "operations": []}

    def run(argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10,
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"})
        report["operations"].append({"argv": argv, "exitCode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr})
        assert result.returncode == 0
        return result.stdout

    def live_profile():
        listing = run(["sudo", "-n", "/usr/bin/cat",
                       "/sys/kernel/security/apparmor/profiles"])
        matches = [line for line in listing.splitlines()
                   if line.startswith(PROFILE_NAME + " (")]
        assert len(matches) <= 1
        return matches[0] if matches else None

    live = live_profile()
    report["liveInitially"] = live
    if action != "cleanup":
        if existed:
            assert live == PROFILE_NAME + " (unconfined)"
        else:
            assert live is None

    if action == "inspect":
        assert not os.path.lexists(stage)
    elif action == "prepare":
        assert not os.path.lexists(stage)
        run(["/usr/sbin/apparmor_parser", "-Q", "-K", str(source)])
        if not existed:
            # The unique root-owned stage is a durable receipt. A hard link
            # creates DEST without overwriting a profile installed by anyone
            # else. Parent cleanup can verify inode identity after a crash.
            run(["sudo", "-n", "install", "-o", "root", "-g", "root", "-m", "0644",
                 str(source), str(stage)])
            checked_profile(stage)
            run(["sudo", "-n", "ln", "--", str(stage), str(DEST)])
            assert checked_profile(DEST).st_ino == stage.stat().st_ino
            assert live_profile() is None
            run(["sudo", "-n", "/usr/sbin/apparmor_parser", "-a", "-K", str(DEST)])
        assert live_profile() == PROFILE_NAME + " (unconfined)"
        checked_profile(DEST)
    else:
        if os.path.lexists(stage):
            owned = owned_stage(stage)
            if os.path.lexists(DEST):
                checked_profile(stage)
                current = checked_profile(DEST)
                assert (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino)
                current_live = live_profile()
                if current_live is not None:
                    assert current_live == PROFILE_NAME + " (unconfined)"
                    run(["sudo", "-n", "/usr/sbin/apparmor_parser", "-R", "-K", str(DEST)])
                    assert live_profile() is None
                run(["sudo", "-n", "/usr/bin/rm", "--", str(DEST)])
            run(["sudo", "-n", "/usr/bin/rm", "--", str(stage)])
    report["finalAbsent"] = not os.path.lexists(DEST)
    report["stageAbsent"] = not os.path.lexists(stage)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
