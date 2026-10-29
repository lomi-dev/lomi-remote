#!/usr/bin/env python3
"""Provide short-lived online TUF key files to the release publisher."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import trust


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("assemble", "refresh"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bundles")
    parser.add_argument("--revision")
    parser.add_argument("--platforms")
    args = parser.parse_args()
    env = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="lomi-online-keys-") as temporary:
        for role, name in (("targets", "LOMI_TUF_TARGETS_KEY"), ("snapshot", "LOMI_TUF_SNAPSHOT_KEY"),
                           ("timestamp", "LOMI_TUF_TIMESTAMP_KEY"), ("index", "LOMI_RELEASE_INDEX_KEY")):
            value = env.pop(name, "")
            if not value:
                raise trust.TrustError(f"required online signing secret is missing: {name}")
            descriptor = os.open(Path(temporary) / f"{role}.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(value)
        command = [sys.executable, str(Path(__file__).with_name("publish_release.py")), args.command,
                   "--tag", args.tag, "--output", args.output, "--key-dir", temporary]
        for name in ("bundles", "revision", "platforms"):
            if getattr(args, name):
                command += ["--" + name, getattr(args, name)]
        return subprocess.run(command, env=env, check=False).returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (trust.TrustError, OSError) as error:
        print(f"release signing setup failed: {error}", file=sys.stderr)
        raise SystemExit(1)
