#!/usr/bin/env python3
"""Build a tag's Host bundle using public pins and ephemeral signing files."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

import build_release
import trust

ROOT = Path(__file__).resolve().parents[1]


def check_tag(tag: str) -> str:
    import re
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if not re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag) or tag != "v" + version:
        raise trust.TrustError("tag must be stable vX.Y.Z and match Cargo.toml workspace.package.version")
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--platform", choices=build_release.PLATFORMS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        version = check_tag(args.tag)
        public_dir = ROOT / "release" / "trust"
        public = trust.loads((public_dir / "release-public.json").read_bytes())
        if args.check:
            print(json.dumps({"version": version, "tag": args.tag, "rootSha256": public["root_sha256"]}))
            return 0
        if not args.platform or args.output is None:
            raise trust.TrustError("build requires --platform and --output")
        system, arch = args.platform.split("-", 1)
        host = trust.loads((ROOT / "release" / "host-config.json").read_bytes())
        env = os.environ.copy()
        for key, value in host["bootstrap"].items():
            if not env.get(key):
                env[key] = value
        target = f"{system}/{arch}/lomiremote" + (".exe" if system == "windows" else "")
        command = [sys.executable, str(ROOT / "release" / "build_release.py"),
                   "--platform", args.platform, "--release-origin", public["origin"],
                   "--artifact-origin", public["origin"] + args.tag + "/",
                   "--target-name", target, "--minimum-profile-schema", str(host["minimumProfileSchema"]),
                   "--public-root", str(public_dir / public["root_file"]),
                   "--public-root-sha256", public["root_sha256"], "--output", str(args.output)]
        with tempfile.TemporaryDirectory(prefix="lomi-release-key-") as temporary:
            if system == "linux":
                key = env.pop("LOMI_LINUX_BOOTSTRAP_KEY", "")
                if not key:
                    raise trust.TrustError("LOMI_LINUX_BOOTSTRAP_KEY must be configured before building Linux releases")
                path = Path(temporary) / "linux-bootstrap.pem"
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w") as stream:
                    stream.write(key)
                command += ["--linux-bootstrap-public-key", str(public_dir / public["linux_bootstrap_public_key_file"]),
                            "--linux-bootstrap-key-sha256", public["linux_bootstrap_key_sha256"],
                            "--linux-bootstrap-signing-key", str(path)]
            if system == "windows":
                signer = env.get("LOMI_WINDOWS_SIGNER_THUMBPRINT", "")
                if not signer:
                    raise trust.TrustError("Windows requires LOMI_WINDOWS_SIGNER_THUMBPRINT and its native private key")
                command += ["--companion-target-name", f"windows/{arch}/lomiremote-host.exe",
                            "--windows-signer-thumbprint", signer]
            subprocess.run(command, env=env, check=True, cwd=ROOT)
        return 0
    except (trust.TrustError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"tag release build failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
