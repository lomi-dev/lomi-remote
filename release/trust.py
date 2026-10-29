#!/usr/bin/env python3
"""Small OpenSSL-backed Ed25519 helpers for the Lomi TUF release trust root."""
from __future__ import annotations

import argparse, base64, hashlib, json, os, re, selectors, shutil, stat, subprocess, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

REPO = "lomi-dev/lomi-remote"
ORIGIN = "https://lomi.dev/remote/releases/"
MAX_TOOL_OUTPUT = 64 * 1024
MAX_METADATA = 4 * 1024 * 1024
_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_ROLES = ("root", "targets", "snapshot", "timestamp")
_KEYS = (*_ROLES, "index", "linux-bootstrap")

class TrustError(RuntimeError):
    pass

def canonical(value) -> bytes:
    """Return the UTF-8 OLPC/TUF canonical JSON representation."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, float):
            raise TrustError("canonical JSON does not permit floating point values")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise TrustError("canonical JSON object keys must be strings")
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
        elif item is not None and type(item) not in (str, int, bool):
            raise TrustError("canonical JSON contains an unsupported value")
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise TrustError("could not encode canonical JSON") from error

def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TrustError("JSON document contains duplicate object keys")
        result[key] = value
    return result

def loads(data: bytes | str):
    """Read JSON while rejecting duplicate keys and floating point numbers."""
    def no_float(_value):
        raise TrustError("JSON document contains a floating point number")
    try:
        return json.loads(data, object_pairs_hook=_unique_object, parse_float=no_float,
                          parse_constant=no_float)
    except TrustError:
        raise
    except (ValueError, UnicodeError, TypeError) as error:
        raise TrustError("JSON document is invalid") from error

def sha256(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def _require(condition: bool, message: str) -> None:
    if not condition: raise TrustError(message)

def _run(command: list[str], *, timeout: int = 30, check: bool = True,
         with_status: bool = False):
    """Run OpenSSL without a shell, bounding output and execution time."""
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, close_fds=True)
    except OSError as error:
        raise TrustError("could not start OpenSSL") from error
    output = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    try:
        for name in output:
            selector.register(getattr(process, name), selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TrustError("OpenSSL operation timed out")
            for key, _ in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if sum(map(len, output.values())) + len(chunk) > MAX_TOOL_OUTPUT:
                    raise TrustError("OpenSSL output exceeded its limit")
                output[key.data].extend(chunk)
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        for name in output:
            stream = getattr(process, name)
            if not stream.closed:
                stream.close()
    if check and code:
        raise TrustError(f"OpenSSL operation failed (exit {code})")
    result = bytes(output["stdout"])
    return (result, code) if with_status else result

def _openssl(openssl=None) -> str:
    command = str(openssl) if openssl is not None else (shutil.which("openssl3") or next(
        (str(path) for path in map(Path, ("/opt/homebrew/opt/openssl@3/bin/openssl",
                                          "/usr/local/opt/openssl@3/bin/openssl")) if path.is_file()),
        "openssl"))
    if not command or "\x00" in command:
        raise TrustError("OpenSSL executable is invalid")
    return command

def _private_file(path: Path) -> Path:
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as error:
        raise TrustError("private key is unavailable") from error
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise TrustError("private key must be a private regular file")
    if not 1 <= info.st_size <= 16 * 1024:
        raise TrustError("private key has an invalid size")
    return path

def public_key(private_path: Path, openssl=None) -> dict:
    raw = _run([_openssl(openssl), "pkey", "-in", str(_private_file(private_path)),
                "-pubout", "-outform", "DER"])
    if len(raw) != 44 or not raw.startswith(_SPKI_PREFIX):
        raise TrustError("private key is not an OpenSSL Ed25519 key")
    return {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": raw[-32:].hex()}}

def create_key(private_path: Path, *, openssl=None) -> dict:
    path = Path(private_path)
    parent = path.parent
    if not parent.is_dir():
        raise TrustError("private key directory must already exist")
    if os.path.lexists(path):
        raise TrustError("refusing to replace an existing private key")
    fd, name = tempfile.mkstemp(prefix=".lomi-key-", dir=parent)
    temp_path = Path(name)
    try:
        os.close(fd)
        os.chmod(temp_path, 0o600)
        _run([_openssl(openssl), "genpkey", "-algorithm", "ED25519", "-out", str(temp_path)])
        os.chmod(temp_path, 0o600)
        if temp_path.stat().st_size > 16 * 1024:
            raise TrustError("generated private key exceeds its size limit")
        public = public_key(temp_path, openssl)
        try:
            os.link(temp_path, path)
        except FileExistsError as error:
            raise TrustError("refusing to replace an existing private key") from error
    except BaseException:
        try: temp_path.unlink()
        except OSError: pass
        raise
    temp_path.unlink()
    return public

def key_id(public: dict) -> str: return sha256(canonical(public))

def sign_bytes(data: bytes, private_path: Path, openssl=None) -> bytes:
    if not isinstance(data, bytes) or len(data) > MAX_METADATA:
        raise TrustError("signed data must be bytes within the metadata size limit")
    _private_file(private_path)
    with tempfile.TemporaryDirectory(prefix="lomi-sign-") as temporary:
        message = Path(temporary) / "message"
        message.write_bytes(data)
        signature = _run([_openssl(openssl), "pkeyutl", "-sign", "-rawin", "-inkey",
                          str(private_path), "-in", str(message)])
    if len(signature) != 64:
        raise TrustError("OpenSSL returned an invalid Ed25519 signature")
    return signature

def verify_bytes(data: bytes, signature: bytes, public: dict, openssl=None) -> bool:
    if (not isinstance(data, bytes) or len(data) > MAX_METADATA
            or not isinstance(signature, bytes) or len(signature) != 64):
        return False
    try:
        if (not isinstance(public, dict) or public.get("keytype") != "ed25519"
                or public.get("scheme") != "ed25519" or not isinstance(public.get("keyval"), dict)):
            return False
        encoded = public["keyval"].get("public")
        if not isinstance(encoded, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", encoded):
            return False
        raw = bytes.fromhex(encoded)
        with tempfile.TemporaryDirectory(prefix="lomi-verify-") as temporary:
            pub_path = Path(temporary) / "public.der"
            msg_path = Path(temporary) / "message"
            sig_path = Path(temporary) / "signature"
            pub_path.write_bytes(_SPKI_PREFIX + raw)
            msg_path.write_bytes(data)
            sig_path.write_bytes(signature)
            _, status = _run([_openssl(openssl), "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform",
                              "DER", "-inkey", str(pub_path), "-in", str(msg_path), "-sigfile",
                              str(sig_path)], check=False, with_status=True)
            return status == 0
    except (TrustError, OSError, ValueError):
        return False

def sign_metadata(signed: dict, private_path: Path, openssl=None) -> dict:
    data = canonical(signed)
    public = public_key(private_path, openssl)
    return {"signed": signed, "signatures": [{"keyid": key_id(public), "sig": sign_bytes(data, private_path, openssl).hex()}]}

def _expiry(value) -> datetime:
    if not isinstance(value, str):
        raise TrustError("metadata expiry must be a timestamp string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise TrustError("metadata expiry is invalid") from error
    if parsed.tzinfo is None:
        raise TrustError("metadata expiry must include a timezone")
    return parsed.astimezone(timezone.utc)

def verify_metadata(document: dict, root_signed: dict, role: str, openssl=None) -> dict:
    """Authenticate one top-level TUF role with its pinned root threshold."""
    _require(isinstance(document, dict) and isinstance(root_signed, dict), "metadata and trusted root must be objects")
    _require(isinstance(role, str) and role in _ROLES, "metadata role is not a supported top-level TUF role")
    _require({"signed", "signatures"} <= document.keys(), "metadata envelope is incomplete")
    signed, signatures = document["signed"], document["signatures"]
    _require(isinstance(signed, dict) and isinstance(signatures, list), "metadata envelope has invalid types")
    roles, keys = root_signed.get("roles"), root_signed.get("keys")
    _require(isinstance(roles, dict) and isinstance(keys, dict) and role in roles,
             "trusted root does not authorize this role")
    role_info = roles[role]
    _require(isinstance(role_info, dict) and isinstance(role_info.get("keyids"), list),
             "trusted root role definition is invalid")
    keyids = role_info["keyids"]
    threshold = role_info.get("threshold")
    _require(type(threshold) is int and threshold >= 1 and all(isinstance(item, str) for item in keyids)
             and len(set(keyids)) == len(keyids) and threshold <= len(keyids),
             "trusted root threshold is invalid")
    authorized = {}
    for kid in keyids:
        public = keys.get(kid)
        if not isinstance(public, dict) or key_id(public) != kid:
            raise TrustError("trusted root contains an invalid key identifier")
        authorized[kid] = public
    contained, valid = set(), set()
    data = canonical(signed)
    for item in signatures:
        _require(isinstance(item, dict) and {"keyid", "sig"} <= item.keys(), "metadata signature entry is invalid")
        kid, encoded = item["keyid"], item["sig"]
        _require(isinstance(kid, str) and kid not in contained, "metadata contains duplicate or invalid signatures")
        contained.add(kid)
        _require(isinstance(encoded, str) and re.fullmatch(r"[0-9a-fA-F]{128}", encoded),
                 "metadata signature encoding is invalid")
        if kid in authorized and verify_bytes(data, bytes.fromhex(encoded), authorized[kid], openssl):
            valid.add(kid)
    _require(len(valid) >= threshold, "metadata signature threshold was not met")
    expected_type = "root" if role == "root" else role
    _require(signed.get("_type") == expected_type, "metadata has an invalid role type")
    version, expires = signed.get("version"), signed.get("expires")
    _require(type(version) is int and version >= 1, "metadata version must be a positive integer")
    _require(_expiry(expires) > datetime.now(timezone.utc), "metadata has expired")
    return signed

def _write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try: path.unlink()
        except OSError: pass
        raise


def initialize(private_dir: Path, public_dir: Path, *, openssl=None) -> dict:
    private_dir, public_dir = Path(private_dir), Path(public_dir)
    private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = private_dir.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise TrustError("private key directory must be a private directory (mode 0700)")
    (public_dir / "metadata").mkdir(mode=0o755, parents=True, exist_ok=True)
    paths = {name: private_dir / f"{name}.pem" for name in _KEYS}
    outputs = [public_dir / "metadata" / "1.root.json", public_dir / "release-public.json", public_dir / "linux-bootstrap.pub.der"]
    if any(os.path.lexists(path) for path in (*paths.values(), *outputs)):
        raise TrustError("refusing to overwrite existing trust keys or public files")
    created, created_outputs = [], []
    try:
        publics = {}
        for name, path in paths.items():
            publics[name] = create_key(path, openssl=openssl)
            created.append(path)
        ids = {name: key_id(publics[name]) for name in _ROLES}
        now = datetime.now(timezone.utc)
        expires = now.replace(year=now.year + 5)
        root_signed = {
            "_type": "root", "spec_version": "1.0.0", "version": 1,
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "consistent_snapshot": False,
            "keys": {ids[name]: publics[name] for name in _ROLES},
            "roles": {name: {"keyids": [ids[name]], "threshold": 1} for name in _ROLES},
        }
        root_document = sign_metadata(root_signed, paths["root"], openssl)
        verify_metadata(root_document, root_signed, "root", openssl)
        root_bytes = canonical(root_document)
        der = _SPKI_PREFIX + bytes.fromhex(publics["linux-bootstrap"]["keyval"]["public"])
        config = {
            "format": 1, "repo": REPO, "origin": ORIGIN,
            "root_file": "metadata/1.root.json", "root_sha256": sha256(root_bytes),
            "index_public_key_base64": base64.b64encode(
                bytes.fromhex(publics["index"]["keyval"]["public"])).decode("ascii"),
            "linux_bootstrap_key_sha256": sha256(der),
            "linux_bootstrap_public_key_file": "linux-bootstrap.pub.der",
        }
        _write_new(outputs[0], root_bytes)
        created_outputs.append(outputs[0])
        _write_new(outputs[2], der)
        created_outputs.append(outputs[2])
        _write_new(outputs[1], canonical(config))
        created_outputs.append(outputs[1])
        return config
    except BaseException:
        for path in (*created, *created_outputs):
            try: path.unlink()
            except OSError: pass
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("initialize", help="create a new offline release trust root")
    init.add_argument("--private-dir", required=True, type=Path)
    init.add_argument("--public-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        print(canonical(initialize(args.private_dir, args.public_dir)).decode("utf-8"))
        return 0
    except (TrustError, OSError) as error:
        parser.exit(1, f"trust initialization failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
