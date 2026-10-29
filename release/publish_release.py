#!/usr/bin/env python3
"""Assemble authenticated Host releases and refresh their signed TUF metadata."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import tempfile
import time
import uuid
import zipfile

import trust
import build_release

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = {f"{system}-{arch}" for system in ("linux", "macos", "windows") for arch in ("x86_64", "aarch64")}
MAX_ARTIFACT = 1024 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise trust.TrustError(message)


def read_json(path: Path, maximum: int = 1024 * 1024):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, "missing or oversized release metadata")
    return trust.loads(path.read_bytes())


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def date_after(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def coordinates(public_dir: Path) -> tuple[dict, dict]:
    config = read_json(public_dir / "release-public.json", 16 * 1024)
    require(config.get("format") == 1 and config.get("repo") == trust.REPO and config.get("origin") == trust.ORIGIN, "release public configuration is inconsistent")
    root = read_json(public_dir / config["root_file"])
    require(trust.sha256(trust.canonical(root)) == config["root_sha256"], "public root digest differs from its pin")
    trust.verify_metadata(root, root["signed"], "root")
    return config, root


def asset_record(path: Path, asset: str | None = None) -> dict:
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_ARTIFACT, "release artifact must be a bounded regular file")
    name = asset or path.name
    require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", name)), "release asset name is invalid")
    return {"asset": name, "size": path.stat().st_size, "sha256": file_hash(path)}


def metadata_chain(targets: dict, root: dict, key_dir: Path, version: int) -> dict[str, bytes]:
    def signed(role: str, payload: dict) -> bytes:
        envelope = trust.sign_metadata(payload, key_dir / f"{role}.pem")
        trust.verify_metadata(envelope, root["signed"], role)
        data = trust.canonical(envelope)
        require(len(data) <= 1024 * 1024, "TUF metadata exceeds the updater limit")
        return data

    def descriptor(data: bytes) -> dict:
        return {"version": version, "length": len(data), "hashes": {"sha256": trust.sha256(data)}}

    target_bytes = signed("targets", {"_type": "targets", "spec_version": "1.0.0", "version": version, "expires": date_after(365), "targets": targets})
    snapshot_bytes = signed("snapshot", {"_type": "snapshot", "spec_version": "1.0.0", "version": version, "expires": date_after(30), "meta": {"targets.json": descriptor(target_bytes)}})
    timestamp_bytes = signed("timestamp", {"_type": "timestamp", "spec_version": "1.0.0", "version": version, "expires": date_after(7), "meta": {"snapshot.json": descriptor(snapshot_bytes)}})
    return {"metadata/targets.json": target_bytes, "metadata/snapshot.json": snapshot_bytes, "metadata/timestamp.json": timestamp_bytes}


def save_chain(output: Path, files: dict, chain: dict[str, bytes]) -> None:
    for logical, data in chain.items():
        role = logical.split("/")[-1].removesuffix(".json")
        version = trust.loads(data)["signed"]["version"]
        path = output / f"tuf-{role}-{version}-{trust.sha256(data)[:16]}.json"
        path.write_bytes(data)
        files[logical] = asset_record(path)


def write_index(output: Path, files: dict, platforms: list[str], tag: str, config: dict, key_dir: Path) -> dict:
    require(re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag) is not None, "release tag must be stable vX.Y.Z")
    require(len(files) <= 128, "release has too many assets")
    index = {"format": 1, "repository": config["repo"], "tag": tag, "version": tag[1:],
             "issuedAt": date_after(0), "expiresAt": date_after(7), "platforms": sorted(platforms), "files": files}
    data = trust.canonical(index)
    require(len(data) <= 128 * 1024, "release index is oversized")
    public = trust.public_key(key_dir / "index.pem")
    require(base64.b64encode(bytes.fromhex(public["keyval"]["public"])).decode() == config["index_public_key_base64"], "index key differs from the configured public key")
    signature = trust.sign_bytes(data, key_dir / "index.pem")
    envelope = {"signed": index, "signature": base64.b64encode(signature).decode("ascii")}
    envelope_bytes = trust.canonical(envelope)
    (output / "release-index.json").write_bytes(envelope_bytes)
    (output / "release-index-recovery.json").write_bytes(envelope_bytes)
    # Optional detached evidence; no reader depends on promoting a file pair.
    (output / "release-index.sig").write_bytes(signature)
    return index


def check_archive(path: Path, directory: Path, manifest: dict, system: str) -> None:
    prefix = "bundle/" if system == "macos" else ""
    declared_files = manifest.get("files", {})
    required = {"lomiremote.exe", "lomi-update-trust.exe", "install.ps1", "lomiremote-host.exe"} if system == "windows" else {"lomiremote", "lomi-update-trust", "install.sh"}
    require(isinstance(declared_files, dict) and required <= declared_files.keys(), "archive build manifest lacks its installer or executables")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) <= 1000 and len(set(names)) == len(names), "archive has duplicate or excessive entries")
        for item in archive.infolist():
            parts = item.filename.rstrip("/").split("/")
            require(not item.filename.startswith("/") and "\\" not in item.filename and all(part not in {"", ".", ".."} for part in parts), "archive contains a traversal path")
            require(((item.external_attr >> 16) & 0o170000) in (0, 0o100000, 0o040000), "archive contains a symlink or special file")
            if item.is_dir() or item.filename.startswith("__MACOSX/"):
                continue
            logical = item.filename.removeprefix(prefix)
            require(item.filename.startswith(prefix) and (logical in declared_files or logical == "build-manifest.json"), "archive contains an undeclared payload")
            expected = file_hash(directory / "bundle" / "build-manifest.json") if logical == "build-manifest.json" else declared_files[logical]
            require(item.file_size <= 256 * 1024 * 1024, "archive payload exceeds its bound")
            digest = hashlib.sha256()
            with archive.open(item) as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            require(digest.hexdigest() == expected, "archive payload differs from its authenticated build manifest")
        require(all(prefix + name in names for name in (*declared_files, "build-manifest.json")), "archive omits declared payload files")


def check_linux_bootstrap(entry: dict, directory: Path, config: dict, primary_name: str) -> None:
    bootstrap = entry["linuxBootstrap"]
    filename = Path(entry["archive"]["url"]).name
    expected = ("LOMI-LINUX-BOOTSTRAP-V1\n" + f"platform={entry['platform']}\ntarget={primary_name}\nversion={entry['version']}\n"
                + f"public-tuf-root-sha256={config['root_sha256']}\narchive={filename}\n"
                + f"archive-size={entry['archive']['size']}\narchive-sha256={entry['archive']['sha256']}\n").encode("ascii")
    manifest = (directory / Path(bootstrap["manifest"]["url"]).name).read_bytes()
    public_der = (directory / Path(bootstrap["publicKey"]["url"]).name).read_bytes()
    signature = (directory / Path(bootstrap["signature"]["url"]).name).read_bytes()
    require(manifest == expected and len(public_der) == 44 and trust.sha256(public_der) == config["linux_bootstrap_key_sha256"], "Linux bootstrap uses a different manifest or trust key")
    public = {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": public_der[-32:].hex()}}
    require(trust.verify_bytes(manifest, signature, public), "Linux bootstrap manifest signature is invalid")
    values = {
        "BOOTSTRAP_ORIGIN": entry["releaseOrigin"], "BOOTSTRAP_PLATFORM": entry["platform"],
        "BOOTSTRAP_TARGET": primary_name, "BOOTSTRAP_VERSION": entry["version"],
        "BOOTSTRAP_ROOT_SHA256": config["root_sha256"], "BOOTSTRAP_KEY_SHA256": config["linux_bootstrap_key_sha256"],
        "BOOTSTRAP_ARCHIVE_NAME": filename, "BOOTSTRAP_ARCHIVE_SIZE": str(entry["archive"]["size"]),
        "BOOTSTRAP_ARCHIVE_SHA256": entry["archive"]["sha256"], "BOOTSTRAP_ARCHIVE_MAX_BYTES": str(build_release.LINUX_BOOTSTRAP_MAX_ARCHIVE_BYTES),
        "BOOTSTRAP_MANIFEST_NAME": Path(bootstrap["manifest"]["url"]).name, "BOOTSTRAP_MANIFEST_SIZE": str(len(manifest)),
        "BOOTSTRAP_SIGNATURE_NAME": Path(bootstrap["signature"]["url"]).name, "BOOTSTRAP_PUBLIC_KEY_NAME": Path(bootstrap["publicKey"]["url"]).name,
    }
    preflight = (ROOT / "release" / "linux-bootstrap.sh.in").read_text()
    for key, value in values.items():
        preflight = preflight.replace("@@" + key + "_SHELL@@", shlex.quote(value))
    require("@@" not in preflight and (directory / Path(bootstrap["preflight"]["url"]).name).read_bytes() == preflight.encode(), "Linux preflight does not match the tagged bootstrap source")


def assemble(bundles: Path, output: Path, tag: str, revision: str, key_dir: Path, public_dir: Path,
             expected_platforms: set[str] | None = None) -> dict:
    require(re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag) is not None, "release tag must be stable vX.Y.Z")
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "release must identify its immutable source commit")
    require(not output.exists() or (output.is_dir() and not any(output.iterdir())), "release output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    config, root = coordinates(public_dir)
    artifact_origin = config["origin"] + tag + "/"
    files, targets, entries, seen = {}, {}, [], set()

    def copy(source: Path, logical: str, asset: str | None = None) -> dict:
        record = asset_record(source, asset)
        destination = output / record["asset"]
        if destination.exists():
            require(file_hash(destination) == record["sha256"], "release assets collide")
        else:
            shutil.copyfile(source, destination)
        require(logical not in files or files[logical] == record, "release logical paths collide")
        files[logical] = record
        return record

    def declared(artifact: dict, directory: Path) -> None:
        require(isinstance(artifact, dict) and set(artifact) == {"url", "sha256", "size"}, "bundle artifact declaration is malformed")
        require(isinstance(artifact["url"], str) and artifact["url"].startswith(artifact_origin), "bundle artifact escaped the versioned release origin")
        filename = artifact["url"][len(artifact_origin):]
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", filename) is not None, "bundle artifact name is invalid")
        record = copy(directory / filename, filename)
        require(record["sha256"] == artifact["sha256"] and record["size"] == artifact["size"], "bundle artifact bytes differ from their declaration")

    for entry_path in sorted(bundles.rglob("installation-entry.json")):
        directory = entry_path.parent
        entry = read_json(entry_path, 64 * 1024)
        platform_name = entry.get("platform")
        require(platform_name in PLATFORMS and platform_name not in seen, "bundle has a duplicate or unsupported platform")
        seen.add(platform_name)
        require(entry.get("format") == 1 and entry.get("version") == tag[1:] and entry.get("releaseOrigin") == artifact_origin, "bundle version or origin differs from the tag release")
        manifest = read_json(directory / "bundle" / "build-manifest.json")
        require(manifest.get("sourceRevision") == revision and manifest.get("version") == tag[1:] and manifest.get("platform") == platform_name and manifest.get("releaseOrigin") == config["origin"], "bundle provenance differs from the tag source")
        require(manifest.get("artifactOrigin") == artifact_origin, "bundle initial-install origin is not version-pinned")
        require(manifest.get("publicTufRootSha256") == config["root_sha256"] and entry["publicRoot"]["sha256"] == config["root_sha256"], "bundle uses another update trust root")
        declared(entry["archive"], directory)
        declared(entry["publicRoot"], directory)
        system, arch = platform_name.split("-", 1)
        check_archive(directory / Path(entry["archive"]["url"]).name, directory, manifest, system)
        primary_name = f"{system}/{arch}/lomiremote" + (".exe" if system == "windows" else "")
        require(manifest.get("tufTargetName") == primary_name, "bundle uses an unexpected TUF target name")
        policies = manifest.get("tufTargetCustom", {})
        policy = policies.get("lomiRelease", {})
        require(set(policy) == {"format", "platform", "version", "minProfileSchema", "maxProfileSchema"} and policy.get("format") == 1 and policy.get("platform") == platform_name and policy.get("version") == tag[1:], "bundle has an invalid signed release policy")
        require(type(policy["minProfileSchema"]) is int and type(policy["maxProfileSchema"]) is int and 0 <= policy["minProfileSchema"] <= policy["maxProfileSchema"], "bundle schema range is invalid")
        names = [primary_name]
        if system == "windows":
            helper = f"windows/{arch}/lomiremote-host.exe"
            require(manifest.get("tufCompanionTargetName") == helper, "Windows helper target is missing")
            signer = policies.get("lomiAuthenticode", {})
            require(signer.get("format") == 1 and re.fullmatch(r"[A-F0-9]{40}", signer.get("thumbprint", "")) is not None, "Windows bundle has no native signer pin")
            names.append(helper)
        for name in names:
            source = directory / "bundle" / "targets" / name
            record = copy(source, "targets/" + name, "target-" + platform_name + "-" + name.rsplit("/", 1)[-1])
            require(record["size"] <= 256 * 1024 * 1024 and record["sha256"] == manifest["files"].get("targets/" + name), "TUF executable hash differs from its build manifest")
            targets[name] = {"length": record["size"], "hashes": {"sha256": record["sha256"]}, "custom": policies}
        catalog_entry = {"platform": platform_name, "archive": entry["archive"]}
        if system == "linux":
            bootstrap = entry["linuxBootstrap"]
            for field in ("preflight", "manifest", "signature", "publicKey"):
                declared(bootstrap[field], directory)
            check_linux_bootstrap(entry, directory, config, primary_name)
            require(file_hash(directory / "install-command.txt") == bootstrap["commandSha256"], "Linux command declaration differs from its bytes")
            catalog_entry["linuxBootstrap"] = bootstrap
        elif system == "macos":
            receipt = read_json(Path(str(directory / Path(entry["archive"]["url"]).name) + ".notarization.json"))
            require(receipt.get("status") == "Accepted" and receipt.get("archive_sha256") == entry["archive"]["sha256"], "macOS archive has no matching Apple acceptance")
            require(receipt.get("team_id") == read_json(ROOT / "release" / "macos-signing.json")["team_id"], "macOS bundle belongs to another publisher")
            require(str(uuid.UUID(receipt.get("submission_id", ""))) == receipt.get("submission_id"), "macOS receipt has no valid Apple submission identifier")
            copy(Path(str(directory / Path(entry["archive"]["url"]).name) + ".notarization.json"), "notarization-" + platform_name + ".json", "notarization-" + platform_name + ".json")
        entries.append(catalog_entry)

    require(seen and (expected_platforms is None or seen == expected_platforms), "release is missing a required platform bundle")
    catalog = {"format": 1, "version": tag[1:], "releaseOrigin": artifact_origin, "sourceRevision": revision,
               "publicRoot": {"url": artifact_origin + "release-root-" + config["root_sha256"] + ".json", "sha256": config["root_sha256"], "size": len(trust.canonical(root))}, "targets": entries}
    (output / "installation-catalog.json").write_bytes(trust.canonical(catalog))
    subprocess.run(["node", str(ROOT / "release" / "bootstrap" / "render.mjs"), str(output / "installation-catalog.json"), str(output)], check=True)
    for name in ("install.sh", "install.ps1", "installation-catalog.json"):
        files[name] = asset_record(output / name)
    for source in sorted((public_dir / "metadata").glob("*.root.json")):
        copy(source, "metadata/" + source.name, "tuf-" + source.name)
    version = int(time.time())
    save_chain(output, files, metadata_chain(targets, root, key_dir, version))
    return write_index(output, files, sorted(seen), tag, config, key_dir)


def gh_download(tag: str, name: str, directory: Path, repo: str) -> Path:
    subprocess.run(["gh", "release", "download", tag, "--repo", repo, "--pattern", name, "--dir", str(directory)], check=True)
    path = directory / name
    require(path.is_file() and not path.is_symlink(), "GitHub did not return the expected release asset")
    return path


def previous_index(tag: str, directory: Path, config: dict) -> tuple[dict, str]:
    index_key = {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": base64.b64decode(config["index_public_key_base64"]).hex()}}
    for name in ("release-index.json", "release-index-recovery.json"):
        try:
            data = gh_download(tag, name, directory, config["repo"]).read_bytes()
            require(len(data) <= 128 * 1024, "previous release index is oversized")
            envelope = trust.loads(data)
            require(isinstance(envelope, dict) and set(envelope) == {"signed", "signature"} and trust.canonical(envelope) == data, "previous release index envelope is malformed")
            signature = base64.b64decode(envelope["signature"], validate=True)
            index = envelope["signed"]
            require(isinstance(index, dict) and trust.verify_bytes(trust.canonical(index), signature, index_key), "previous release index has an invalid signature")
            require(index.get("repository") == config["repo"] and index.get("tag") == tag and index.get("version") == tag[1:], "previous index has incorrect release coordinates")
            return index, name
        except (trust.TrustError, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError):
            continue
    raise trust.TrustError("no authenticated release index or recovery copy is available")


def refresh(tag: str, output: Path, key_dir: Path, public_dir: Path, state: dict | None = None) -> dict:
    config, root = coordinates(public_dir)
    require(re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag) is not None, "refresh requires a stable release tag")
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="lomi-refresh-") as temporary:
        directory = Path(temporary)
        index, source = previous_index(tag, directory, config)
        if state is not None:
            state["source"] = source
        descriptor = index["files"]["metadata/targets.json"]
        path = gh_download(tag, descriptor["asset"], directory, config["repo"])
        require(path.stat().st_size == descriptor["size"] and file_hash(path) == descriptor["sha256"], "previous targets metadata differs from its signed inventory")
        # Authenticate the previously approved payload before allowing online
        # keys to renew it. Expired targets require an operator-led new release.
        document = read_json(path)
        signed = trust.verify_metadata(document, root["signed"], "targets")
        version = max(int(time.time()), signed["version"] + 1)
        files = dict(index["files"])
        save_chain(output, files, metadata_chain(signed["targets"], root, key_dir, version))
        return write_index(output, files, index["platforms"], tag, config, key_dir)


def upload(tag: str, output: Path, *, publish: bool = True) -> None:
    require(re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", tag) is not None, "invalid release tag")
    existing = subprocess.run(["gh", "release", "view", tag, "--repo", trust.REPO, "--json", "isDraft"], capture_output=True, text=True)
    if existing.returncode == 0:
        require(trust.loads(existing.stdout).get("isDraft") is True, "published release assets cannot be rebuilt or overwritten")
    else:
        subprocess.run(["gh", "release", "create", tag, "--repo", trust.REPO, "--verify-tag", "--draft", "--title", tag, "--generate-notes"], check=True)
    subprocess.run(["gh", "release", "upload", tag, "--repo", trust.REPO, "--clobber", *map(str, sorted(output.iterdir()))], check=True)
    if publish:
        latest = subprocess.run(["gh", "release", "view", "--repo", trust.REPO, "--json", "tagName"], capture_output=True, text=True)
        if latest.returncode == 0:
            previous = trust.loads(latest.stdout)["tagName"]
            require(re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", previous) is not None, "current latest release has an unsupported tag")
            require(tuple(map(int, tag[1:].split("."))) > tuple(map(int, previous[1:].split("."))), "a new release must be newer than the published latest version")
        subprocess.run(["gh", "release", "edit", tag, "--repo", trust.REPO, "--draft=false", "--latest"], check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("assemble", "upload", "refresh"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bundles", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--platforms", help="comma-separated exact required platform set")
    parser.add_argument("--key-dir", type=Path)
    parser.add_argument("--public-dir", type=Path, default=ROOT / "release" / "trust")
    parser.add_argument("--draft", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "upload":
            upload(args.tag, args.output, publish=not args.draft)
        elif args.command == "assemble":
            require(args.bundles is not None and args.key_dir is not None and args.revision is not None, "assembly requires bundles, keys and source revision")
            result = assemble(args.bundles, args.output, args.tag, args.revision, args.key_dir, args.public_dir,
                              set(args.platforms.split(",")) if args.platforms else None)
            print(f"Prepared {result['tag']} for {', '.join(result['platforms'])}")
        else:
            require(args.key_dir is not None, "refresh requires online signing keys")
            state = {}
            refresh(args.tag, args.output, args.key_dir, args.public_dir, state)
            # Only online metadata/index files are replaced; executable hashes
            # came from the authenticated previous release and never change.
            # New metadata assets have immutable names. Promote the single
            # signed envelope only after every referenced asset is available.
            metadata = [p for p in sorted(args.output.iterdir()) if not p.name.startswith("release-index")]
            subprocess.run(["gh", "release", "upload", args.tag, "--repo", trust.REPO, *map(str, metadata)], check=True)
            subprocess.run(["gh", "release", "upload", args.tag, "--repo", trust.REPO, "--clobber", str(args.output / "release-index.sig")], check=True)
            # GitHub --clobber deletes before uploading. Replace the other
            # pointer first; never delete the sole authenticated source even
            # when a retry starts after an interrupted primary replacement.
            pointers = ["release-index-recovery.json", "release-index.json"]
            if state["source"] == "release-index-recovery.json":
                pointers.reverse()
            for name in pointers:
                subprocess.run(["gh", "release", "upload", args.tag, "--repo", trust.REPO, "--clobber", str(args.output / name)], check=True)
        return 0
    except (trust.TrustError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"release publication failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
