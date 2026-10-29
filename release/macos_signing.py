#!/usr/bin/env python3
"""Developer ID signing and notarization through an existing Keychain profile."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time
import uuid
import zipfile


DEFAULT_CONFIG = Path(__file__).with_name("macos-signing.json")
MAX_TOOL_OUTPUT = 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024


class MacOSSigningError(RuntimeError):
    pass


@dataclass(frozen=True)
class MacOSSigningConfig:
    identity: str
    team_id: str
    notary_profile: str
    keychain: Path | None = None
    timeout_seconds: int = 1800

    def __post_init__(self) -> None:
        if not isinstance(self.team_id, str) or not re.fullmatch(r"[A-Z0-9]{10}", self.team_id):
            raise MacOSSigningError("macOS Team ID must have ten uppercase letters or digits")
        if not isinstance(self.identity, str) or not (
            re.fullmatch(r"[A-Fa-f0-9]{40}", self.identity)
            or re.fullmatch(r"Developer ID Application: [^\x00-\x1f\x7f]+ \([A-Z0-9]{10}\)", self.identity)
        ):
            raise MacOSSigningError("select an exact Developer ID Application identity or its 40-hex fingerprint")
        if not isinstance(self.notary_profile, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.notary_profile):
            raise MacOSSigningError("notarization profile name is invalid")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 3600:
            raise MacOSSigningError("notarization timeout must be between 1 and 3600 seconds")
        if self.keychain is not None:
            path = Path(self.keychain)
            if not path.is_absolute() or re.search(r"[\x00-\x1f\x7f]", str(path)):
                raise MacOSSigningError("Keychain path must be absolute and contain no control characters")
            object.__setattr__(self, "keychain", path)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise MacOSSigningError("signing configuration contains duplicate keys")
        value[key] = item
    return value


def load_config(*, identity=None, team_id=None, notary_profile=None, keychain=None,
                config_path: Path | None = None) -> MacOSSigningConfig:
    path = Path(config_path) if config_path is not None else DEFAULT_CONFIG
    try:
        with path.open("rb") as source:
            raw = source.read(16 * 1024 + 1)
        if len(raw) > 16 * 1024:
            raise MacOSSigningError("public signing configuration exceeds 16 KiB")
        config = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, ValueError, UnicodeError) as error:
        raise MacOSSigningError("could not read the public macOS signing configuration") from error
    if not isinstance(config, dict) or set(config) != {"format", "identity", "team_id", "notary_profile"} or type(config["format"]) is not int or config["format"] != 1:
        raise MacOSSigningError("public macOS signing configuration has an unsupported format")
    return MacOSSigningConfig(
        identity=identity or os.environ.get("LOMI_MACOS_SIGNING_IDENTITY") or config["identity"],
        team_id=team_id or os.environ.get("LOMI_MACOS_TEAM_ID") or config["team_id"],
        notary_profile=notary_profile or os.environ.get("LOMI_MACOS_NOTARY_PROFILE") or config["notary_profile"],
        keychain=keychain or os.environ.get("LOMI_MACOS_KEYCHAIN") or None,
    )


def _run(command: list[str], *, timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess:
    """Bound both pipes while waiting; never print command output or credentials."""
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, close_fds=True)
    except OSError as error:
        raise MacOSSigningError(f"could not start {command[0]}") from error
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    try:
        for name in buffers:
            selector.register(getattr(process, name), selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MacOSSigningError(f"{command[0]} timed out; inspect notarization history before retrying a submission")
            for selected, _ in selector.select(min(remaining, 0.25)):
                chunk = os.read(selected.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(selected.fileobj)
                    selected.fileobj.close()
                    continue
                if sum(map(len, buffers.values())) + len(chunk) > MAX_TOOL_OUTPUT:
                    raise MacOSSigningError(f"{command[0]} exceeded its output limit")
                buffers[selected.data].extend(chunk)
        try:
            result_code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise MacOSSigningError(f"{command[0]} timed out") from error
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        for name in buffers:
            getattr(process, name).close()
    result = subprocess.CompletedProcess(command, result_code,
        buffers["stdout"].decode("utf-8", errors="replace"),
        buffers["stderr"].decode("utf-8", errors="replace"))
    if check and result.returncode:
        raise MacOSSigningError(f"{command[0]} failed (exit {result.returncode}); check tool access and the selected signing identity")
    return result


def _notary_options(config: MacOSSigningConfig) -> list[str]:
    options = ["--keychain-profile", config.notary_profile]
    if config.keychain is not None:
        options += ["--keychain", str(config.keychain)]
    return options


def preflight(config: MacOSSigningConfig, *, check_notary: bool = True) -> dict:
    if platform.system() != "Darwin":
        raise MacOSSigningError("macOS signing requires a macOS runner")
    for tool in ("security", "codesign", "xcrun"):
        if not shutil.which(tool):
            raise MacOSSigningError(f"required signing tool is missing: {tool}")
    command = ["security", "find-identity", "-v", "-p", "codesigning"]
    if config.keychain is not None:
        command.append(str(config.keychain))
    available = re.findall(r'^\s*\d+\) ([A-Fa-f0-9]{40}) "([^"\r\n]+)"',
                           _run(command).stdout, re.MULTILINE)
    matches = [(fingerprint.upper(), name) for fingerprint, name in available
               if fingerprint.upper() == config.identity.upper() or name == config.identity]
    if not matches:
        raise MacOSSigningError("the selected Developer ID identity and private key are not available in this Keychain")
    if len(matches) != 1:
        raise MacOSSigningError("the certificate name is ambiguous; select its exact 40-hex fingerprint")
    fingerprint, name = matches[0]
    if not name.startswith("Developer ID Application: ") or not name.endswith(f" ({config.team_id})"):
        raise MacOSSigningError("Developer ID certificate does not belong to the configured Team ID")
    if check_notary:
        result = _run(["xcrun", "notarytool", "history", *_notary_options(config),
                       "--output-format", "json"], check=False)
        if result.returncode:
            raise MacOSSigningError(
                f"notarization profile {config.notary_profile!r} is unavailable or its credentials failed; "
                f"run locally: xcrun notarytool store-credentials {config.notary_profile!r} --team-id {config.team_id}")
        try:
            history = json.loads(result.stdout)
        except ValueError as error:
            raise MacOSSigningError("Apple returned an invalid notarization history response") from error
        if not isinstance(history, dict) or not isinstance(history.get("history"), list):
            raise MacOSSigningError("Apple returned an invalid notarization history response")
    return {"identity": fingerprint, "team_id": config.team_id,
            "notary_profile": config.notary_profile, "notary_checked": check_notary}


def _regular_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise MacOSSigningError("signing input must be a regular file, never a symlink")
        return info
    except OSError as error:
        raise MacOSSigningError("signing input is unavailable") from error


def sign_file(path: Path, config: MacOSSigningConfig) -> None:
    path = Path(path).absolute()
    info = _regular_file(path)
    identity = preflight(config, check_notary=False)["identity"]
    mode = stat.S_IMODE(info.st_mode)
    command = ["codesign", "--force", "--options", "runtime", "--timestamp", "--sign", identity]
    if config.keychain is not None:
        command += ["--keychain", str(config.keychain)]
    try:
        path.chmod(mode | stat.S_IWUSR)
        _run([*command, str(path)], timeout=120)
    finally:
        path.chmod(mode)
    _run(["codesign", "--verify", "--strict", str(path)])
    details = _run(["codesign", "-dv", "--verbose=4", str(path)])
    metadata = details.stdout + details.stderr
    if f"TeamIdentifier={config.team_id}\n" not in metadata or "Authority=Developer ID Application:" not in metadata:
        raise MacOSSigningError("signed file has an unexpected Developer ID publisher or Team ID")
    if not re.search(r"^Timestamp=.+$", metadata, re.MULTILINE):
        raise MacOSSigningError("signed file does not have a secure timestamp")
    with path.open("rb") as source:
        magic = source.read(4)
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca") and "(runtime)" not in metadata:
        raise MacOSSigningError("signed Mach-O executable does not have the hardened runtime")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
        json.dump(value, destination, sort_keys=True, indent=2)
        destination.write("\n")


def notarize_archive(archive: Path, config: MacOSSigningConfig) -> dict:
    archive = Path(archive).absolute()
    info = _regular_file(archive)
    if archive.suffix.lower() != ".zip" or not 0 < info.st_size <= MAX_ARCHIVE_BYTES or not zipfile.is_zipfile(archive):
        raise MacOSSigningError("notarization requires a regular ZIP no larger than 1 GiB")
    receipt_path = Path(str(archive) + ".notarization.json")
    log_path = Path(str(archive) + ".notarization-log.json")
    if receipt_path.exists() or receipt_path.is_symlink() or log_path.exists() or log_path.is_symlink():
        raise MacOSSigningError("notarization evidence already exists; inspect the prior submission before resubmitting")
    receipt = {"format": 1, "archive": archive.name, "archive_sha256": _sha256(archive),
               "team_id": config.team_id, "identity": config.identity,
               "notary_profile": config.notary_profile, "submission_id": None, "status": "SubmissionFailed"}
    pending_path = Path(str(archive) + ".notarization.pending")
    try:
        _write_json(pending_path, {**receipt, "status": "Submitting", "process_id": os.getpid()})
    except FileExistsError as error:
        raise MacOSSigningError("a notarization submission is already reserved; inspect its pending record and Apple history") from error
    try:
        # A prior invocation may have completed between the first check and
        # acquisition. Recheck under the exclusive reservation before uploading.
        if receipt_path.exists() or receipt_path.is_symlink() or log_path.exists() or log_path.is_symlink():
            pending_path.unlink()
            raise MacOSSigningError("notarization evidence already exists; inspect the prior submission before resubmitting")
        return _submit_archive(archive, config, receipt, receipt_path, log_path)
    finally:
        # An interrupted command can already have uploaded to Apple. Leave its
        # reservation until an operator checks history, preventing blind retries.
        if receipt_path.is_file():
            pending_path.unlink(missing_ok=True)


def _submit_archive(archive: Path, config: MacOSSigningConfig, receipt: dict,
                    receipt_path: Path, log_path: Path) -> dict:
    try:
        result = _run(["xcrun", "notarytool", "submit", str(archive), *_notary_options(config),
                       "--wait", "--timeout", f"{config.timeout_seconds}s", "--output-format", "json"],
                      timeout=config.timeout_seconds + 60, check=False)
    except MacOSSigningError:
        _write_json(receipt_path, receipt)
        raise
    try:
        response = json.loads(result.stdout)
        submission_id = str(uuid.UUID(response["id"]))
        receipt["submission_id"] = submission_id
        status = response["status"]
        if status not in ("Accepted", "Invalid", "Rejected", "In Progress"):
            raise ValueError("invalid status")
    except (ValueError, KeyError, TypeError, AttributeError):
        receipt["status"] = "InvalidResponse"
        _write_json(receipt_path, receipt)
        raise MacOSSigningError("Apple did not return a valid submission identifier and notarization status")
    receipt.update(submission_id=submission_id, status=status)
    if _sha256(archive) != receipt["archive_sha256"]:
        receipt["status"] = "ArchiveChanged"
    elif result.returncode:
        receipt["status"] = "ToolFailure"
        receipt["apple_status"] = status
    _write_json(receipt_path, receipt)
    if receipt["status"] != "Accepted":
        try:
            log = _run(["xcrun", "notarytool", "log", submission_id, *_notary_options(config)], check=False)
            if not log.returncode:
                log_value = json.loads(log.stdout)
                if isinstance(log_value, dict):
                    _write_json(log_path, log_value)
        except (MacOSSigningError, ValueError, OSError):
            pass
        raise MacOSSigningError(f"notarization was not accepted ({receipt['status']}); submission {submission_id}; see {receipt_path.name}")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "sign", "notarize"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path)
        command.add_argument("--identity")
        command.add_argument("--team-id")
        command.add_argument("--notary-profile")
        command.add_argument("--keychain", type=Path)
        if name == "check":
            command.add_argument("--signing-only", action="store_true")
        else:
            command.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        config = load_config(identity=args.identity, team_id=args.team_id, notary_profile=args.notary_profile,
                             keychain=args.keychain, config_path=args.config)
        if args.command == "check":
            result = preflight(config, check_notary=not args.signing_only)
        elif args.command == "sign":
            sign_file(args.path, config)
            result = {"signed": str(args.path), "team_id": config.team_id}
        else:
            preflight(config)
            result = notarize_archive(args.path, config)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (MacOSSigningError, OSError) as error:
        print(f"macOS signing: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
