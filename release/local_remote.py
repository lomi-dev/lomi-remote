"""SSH transport for isolated local-release builds; never stores passwords."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid

import trust


class RemoteReleaseError(ValueError):
    pass


def ssh_args(host: str, options=()) -> list[str]:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*@[A-Za-z0-9][A-Za-z0-9_.-]*", host):
        raise ValueError("SSH destination must be USER@HOST without shell syntax")
    result = ["ssh"]
    for option in options:
        result += ["-o", option]
    sockets = Path.home() / ".cache/lomi-remote-ssh"
    sockets.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = sockets.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("SSH control directory must be owned by the current user")
    sockets.chmod(0o700)
    result += ["-o", "ControlMaster=auto", "-o", "ControlPersist=600",
               "-o", "ControlPath=" + str(sockets / "cm-%C")]
    return result + [host]


def remote_command(host, options, argv, **kwargs):
    try:
        return subprocess.run(ssh_args(host, options) + [shlex.join(map(str, argv))],
                              check=True, **kwargs)
    except subprocess.CalledProcessError as error:
        raise RemoteReleaseError(f"remote command failed with status {error.returncode}; see output above") from None


def remote_home(host, options) -> str:
    result = remote_command(host, options, ["python3", "-c",
        "import json,pathlib;print(json.dumps(str(pathlib.Path.home())))"],
        stdout=subprocess.PIPE, text=True)
    home = json.loads(result.stdout)
    if not isinstance(home, str) or not home.startswith("/") or any(c in home for c in "\r\n\0"):
        raise ValueError("remote account returned an invalid home directory")
    return home


def put_file(host, options, source: Path, destination: str, mode=0o600):
    script = """import os,pathlib,shutil,sys
os.umask(0o077)
p=pathlib.Path(sys.argv[1]);p.parent.mkdir(parents=True,exist_ok=True)
with p.open('wb') as f: shutil.copyfileobj(sys.stdin.buffer,f)
os.chmod(p,int(sys.argv[2],8))
"""
    with source.open("rb") as data:
        remote_command(host, options, ["python3", "-c", script, destination, oct(mode)], stdin=data)


REMOTE_BUILD = """import json,os,pathlib,subprocess,sys,tarfile
os.umask(0o077)
stage=pathlib.Path(sys.argv[1]);origin,artifact,platform=sys.argv[2:]
with tarfile.open(stage/'input.tar') as archive:
    archive.extractall(stage,filter='data')
(stage/'input.tar').unlink()
source=stage/'source';public=stage/'public';key=stage/'linux-bootstrap.pem'
key.chmod(0o600)
config=json.loads((public/'release-public.json').read_text())
host=json.loads((source/'release/host-config.json').read_text())
env=os.environ.copy()
env['PATH']=str(pathlib.Path.home()/'.cargo/bin')+os.pathsep+env.get('PATH','/usr/bin:/bin')
env['CARGO_TARGET_DIR']=str(pathlib.Path.home()/'.cache/lomi-remote-local-target')
env.update(host['bootstrap'])
command=[sys.executable,str(source/'release/build_release.py'),'--platform',platform,
    '--release-origin',origin,'--artifact-origin',artifact,
    '--target-name','linux/x86_64/lomiremote',
    '--minimum-profile-schema',str(host['minimumProfileSchema']),
    '--public-root',str(public/config['root_file']),
    '--public-root-sha256',config['root_sha256'],
    '--linux-bootstrap-public-key',str(public/config['linux_bootstrap_public_key_file']),
    '--linux-bootstrap-key-sha256',config['linux_bootstrap_key_sha256'],
    '--linux-bootstrap-signing-key',str(key),
    '--local-test-ca',str(stage/'ca.der'),'--output',str(stage/'output')]
try:
    result=subprocess.run(command,cwd=source,env=env)
    if result.returncode: sys.exit(result.returncode)
finally:
    key.unlink(missing_ok=True)
"""


def _extract_data(archive: Path, destination: Path):
    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")


def build_remote(host, ssh_options, source: Path, public: Path, ca_der: Path,
                 bootstrap_key: Path, output: Path, origin: str,
                 artifact_origin: str, platform: str):
    if platform != "linux-x86_64":
        raise ValueError("remote local builds currently support Linux x86_64")
    public, bootstrap_key = Path(public).resolve(), Path(bootstrap_key).resolve()
    if bootstrap_key.parent != public.parent / "devkeys":
        raise ValueError("only the isolated local state's bootstrap key may be transferred")
    info = bootstrap_key.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("development bootstrap key must be a private regular file")
    config = trust.loads((public / "release-public.json").read_bytes())
    production = trust.loads((source / "release/trust/release-public.json").read_bytes())
    if config["root_sha256"] == production["root_sha256"]:
        raise ValueError("remote local builds require a separate development trust root")
    home = remote_home(host, ssh_options)
    stage = home + "/.local/share/lomi-remote-local/builds/" + uuid.uuid4().hex
    remote_command(host, ssh_options, ["python3", "-c",
        "import os,pathlib,sys;os.umask(0o077);pathlib.Path(sys.argv[1]).mkdir(parents=True,mode=0o700)", stage])
    with tempfile.TemporaryDirectory(prefix="lomi-local-transfer-") as temporary:
        temporary = Path(temporary)
        package = temporary / "input.tar"
        with tarfile.open(package, "w") as archive:
            archive.add(source, arcname="source", recursive=True)
            archive.add(public, arcname="public", recursive=True)
            archive.add(ca_der, arcname="ca.der", recursive=False)
            archive.add(bootstrap_key, arcname="linux-bootstrap.pem", recursive=False)
        put_file(host, ssh_options, package, stage + "/input.tar")
        try:
            remote_command(host, ssh_options, ["python3", "-c", REMOTE_BUILD,
                stage, origin, artifact_origin, platform])
            result = temporary / "output.tar"
            with result.open("wb") as stream:
                remote_command(host, ssh_options, ["tar", "-C", stage + "/output", "-cf", "-", "."], stdout=stream)
            if output.exists():
                raise ValueError("local output already exists; refusing to overwrite it")
            output.mkdir(parents=True, mode=0o700)
            _extract_data(result, output)
        finally:
            # Cleanup is restricted to this invocation's unpredictable private
            # staging directory; the shared Cargo cache remains available.
            remote_command(host, ssh_options, ["python3", "-c",
                "import pathlib,shutil,sys;p=pathlib.Path(sys.argv[1]);shutil.rmtree(p)", stage])


class ForwardHandle:
    """Own one exact forward on a reusable SSH master, not the whole master."""

    def __init__(self, host, options, specification):
        self.host, self.options, self.specification = host, options, specification
        self.returncode = None
        self.last_check = 0.0

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        if time.monotonic() - self.last_check < 1:
            return None
        self.last_check = time.monotonic()
        command = ssh_args(self.host, self.options)
        command[1:1] = ["-O", "check"]
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=3)
        if result.returncode:
            self.returncode = result.returncode
        return self.returncode

    def terminate(self):
        if self.returncode is not None:
            return
        command = ssh_args(self.host, self.options)
        command[1:1] = ["-O", "cancel", "-R", self.specification]
        result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.returncode = result.returncode
        if result.returncode:
            raise RemoteReleaseError("could not cancel the owned SSH reverse forward")

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.terminate()


def start_forward(host, ssh_options, port):
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("invalid local HTTPS port")
    # Establish/reuse a master with a finite command before supervising the
    # forwarding client, so first-time SSH authentication happens only once.
    remote_home(host, ssh_options)
    command = ssh_args(host, ssh_options)
    specification = f"127.0.0.1:{port}:127.0.0.1:{port}"
    command[1:1] = ["-O", "forward", "-o", "ExitOnForwardFailure=yes", "-R", specification]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    if result.returncode:
        raise RemoteReleaseError("could not open reverse SSH port; another forward may own it")
    return ForwardHandle(host, ssh_options, specification)


def install_remote(host, ssh_options, ca_pem: Path, origin: str):
    if origin != "https://127.0.0.1:18443/remote/releases/":
        raise ValueError("local installation must use the private loopback endpoint")
    home = remote_home(host, ssh_options)
    ca = home + "/.local/share/lomi-remote-local/client-ca.pem"
    put_file(host, ssh_options, Path(ca_pem), ca)
    # The existing serve --ssh process owns the reverse forwarding lifetime.
    # Both curl stages inherit the CA; installed Rust binaries embed that CA.
    script = "\n".join([
        "set -euo pipefail",
        "export PATH=" + shlex.quote(home + "/.local/bin:" + home + "/.cargo/bin") + ':"$PATH"',
        "export CURL_CA_BUNDLE=" + shlex.quote(ca),
        "export LOMI_PROFILE_DIR=" + shlex.quote(home + "/.local/share/lomi-remote-local-test/profile"),
        "export LOMI_INSTALL_DIR=" + shlex.quote(home + "/.local/lib/lomi-remote-local-test"),
        "curl -fsSL https://127.0.0.1:18443/remote/install.sh | sh",
    ])
    remote_command(host, ssh_options, ["bash", "-c", script])
