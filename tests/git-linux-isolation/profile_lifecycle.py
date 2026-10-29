"""Exercise the real profile state machine with isolated filesystem commands."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import profile_prerequisite as profile

TOKEN = "1" * 32


def scenario(interruption):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        dest = root / "profile"
        stage = root / ("stage-" + TOKEN)
        operations = []
        loaded = False

        def checked(path):
            metadata = path.lstat()
            assert stat.S_ISREG(metadata.st_mode)
            assert hashlib.sha256(path.read_bytes()).hexdigest() == profile.EXPECTED
            return metadata

        def owned(path):
            metadata = path.lstat()
            assert stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o6022 == 0
            return metadata

        def command(argv, **_):
            nonlocal loaded
            operations.append(argv)
            if argv[0] == "sudo" and argv[2] == "/usr/bin/cat":
                return SimpleNamespace(returncode=0,
                    stdout="lomi-git-bwrap-experimental (unconfined)\n" if loaded else "",
                    stderr="")
            if argv[0] == "sudo" and argv[2] == "install":
                if interruption == "during-install":
                    Path(argv[-1]).write_bytes(b"partial")
                else:
                    shutil.copyfile(argv[-2], argv[-1])
                os.chmod(argv[-1], 0o644)
                if interruption == "during-install":
                    raise KeyboardInterrupt
            elif argv[0] == "sudo" and argv[2] == "ln":
                os.link(argv[-2], argv[-1])
                if interruption == "after-link":
                    raise KeyboardInterrupt
            elif argv[0] == "sudo" and argv[2] == "/usr/sbin/apparmor_parser":
                if interruption == "load-failure" and "-a" in argv:
                    return SimpleNamespace(returncode=1, stdout="", stderr="injected")
                if "-a" in argv:
                    loaded = True
                elif "-R" in argv:
                    loaded = False
            elif argv[0] == "sudo" and argv[2] == "/usr/bin/rm":
                os.unlink(argv[-1])
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        def call(action):
            with patch.object(profile, "DEST", dest), \
                 patch.object(profile, "STAGE_PREFIX", str(root / "stage-")), \
                 patch.object(profile, "checked_profile", checked), \
                 patch.object(profile, "owned_stage", owned), \
                 patch.object(profile.subprocess, "run", command), \
                 patch.object(sys, "argv", ["profile_prerequisite.py", action, TOKEN]), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                profile.main()
                return json.loads(output.getvalue())

        assert call("inspect")["initiallyAbsent"]
        interrupted = False
        try:
            call("prepare")
        except (AssertionError, KeyboardInterrupt):
            interrupted = True
        assert interrupted, "injected interruption did not happen"
        assert stage.exists(), "durable ownership receipt must precede mutation"
        if dest.exists():
            assert (stage.stat().st_dev, stage.stat().st_ino) == (dest.stat().st_dev, dest.stat().st_ino)
        result = call("cleanup")
        assert result["finalAbsent"] and result["stageAbsent"]
        assert not loaded
        assert not stage.exists() and not dest.exists()
        assert not any("-R" in argv for argv in operations), "never-loaded profile was unloaded"
        assert any(argv[0] == "sudo" and argv[2] == "/usr/bin/rm" for argv in operations)


def existing_profile():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        dest = root / "profile"
        shutil.copyfile(Path(profile.__file__).with_name("bwrap.apparmor"), dest)
        os.chmod(dest, 0o644)
        with patch.object(profile, "DEST", dest), \
             patch.object(profile, "STAGE_PREFIX", str(root / "stage-")), \
             patch.object(profile, "checked_profile", lambda p: p.lstat()), \
             patch.object(profile.subprocess, "run", lambda *_args, **_kwargs:
                 SimpleNamespace(returncode=0,
                     stdout="lomi-git-bwrap-experimental (unconfined)\n", stderr="")), \
             patch.object(sys, "argv", ["profile_prerequisite.py", "inspect", TOKEN]), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            profile.main()
            assert not json.loads(output.getvalue())["initiallyAbsent"]
        assert dest.exists()


def live_profile_without_file():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        dest = root / "profile"
        with patch.object(profile, "DEST", dest), \
             patch.object(profile, "STAGE_PREFIX", str(root / "stage-")), \
             patch.object(profile.subprocess, "run", lambda *_args, **_kwargs:
                 SimpleNamespace(returncode=0,
                     stdout="lomi-git-bwrap-experimental (unconfined)\n", stderr="")), \
             patch.object(sys, "argv", ["profile_prerequisite.py", "inspect", TOKEN]), \
             contextlib.redirect_stdout(io.StringIO()):
            try:
                profile.main()
            except AssertionError:
                pass
            else:
                raise AssertionError("preexisting live profile must block ownership")
        assert not dest.exists()


if __name__ == "__main__":
    for point in ("load-failure", "after-link", "during-install"):
        scenario(point)
    existing_profile()
    live_profile_without_file()
    print(json.dumps({"checksPassed": 5, "checks": [
        "install-success-load-failure-owned-cleanup",
        "interrupted-after-link-owned-cleanup",
        "interrupted-during-install-stage-cleanup",
        "preexisting-profile-not-owned",
        "preexisting-live-profile-without-file-refused"]}))
