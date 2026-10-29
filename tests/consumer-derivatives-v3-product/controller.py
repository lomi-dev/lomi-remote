"""Private, source-bound Consumer v3 PostgreSQL qualification controller.

Importing this file is inert.  The only execution selector is ``--run`` and
it is accepted only after exact local integrator and independent-review
receipts validate against the private bundle's controller and manifest hashes.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit
import uuid

HERE = Path(__file__).resolve().parent
WORKSPACE = Path("/Users/woro/Documents/Lomi")
PROJECT = WORKSPACE / "lomi-remote"
PACKAGE_REL = "lomi-remote/staging/consumer-derivatives-v3-product-successor"
PACKAGE = HERE / "inputs" / PACKAGE_REL
AUTH = HERE / "inputs/auth-app"
LOCAL_BUNDLE_FILES = (
    "admission.py", "capture.sql", "controller.py", "evidence.py",
    "prepare.py", "test_controller.py",
    "helper_denials.py", "test_helper_denials.py",
    "owner_state_denials.py", "test_owner_state_denials.py",
    "s7_plans.py", "test_s7_plans.py",
    "s7_spec.py", "test_s7_spec.py",
    "s7_evidence.py", "test_s7_evidence.py",
)
CAPTURE_NAME = "capture.sql"
ORIGINAL_DEADLINE = 900
WORK_DEADLINE = 840
CLEANUP_DEADLINE = 60
PROCESS_OUTPUT_LIMIT = 1024 * 1024
CATALOG_OUTPUT_LIMIT = 64 * 1024 * 1024
PROCESS_FILE_LIMIT = 64 * 1024 * 1024
PORT = "55439"
PINNED_POSTGRES_TEXT_VERSION = "18.6 (Homebrew)"
PINNED_POSTGRES_SERVER_VERSION_NUM = "180006"
SOURCE_AFTER_FAILURE_STATUS = "NOT_VERIFIED_AFTER_FAILURE"
BUN_PATH = Path("/tmp/bun-v1.4.2/bun-darwin-aarch64/bun")
BUN_CANONICAL_PATH = Path("/private/tmp/bun-v1.4.2/bun-darwin-aarch64/bun")
BUN_SHA256 = "35d20dd0263e5c950194434b925454fdfa9ba6e4467da960410fa05b08a7a5b5"
PRISMA_CLI_PATH = WORKSPACE / "auth-app/node_modules/prisma/build/index.js"
PRISMA_CLI_SHA256 = "763611d694b08952ced7c5abb3b9d61906fed0a8997d9214ac918a43928e0fc8"
PRISMA_SCHEMA_ENGINE_PATH = WORKSPACE / "auth-app/node_modules/@prisma/engines/schema-engine-darwin-arm64"
PRISMA_SCHEMA_ENGINE_SHA256 = "ee46310d1c0edb2b55eed39264828c3f35c5334d3a19930b44fb1dba56cdba7e"
PRISMA_MIGRATION_TIMEOUT = 120
PRISMA_PROJECT_CHILD = "prisma-project"
DATABASES = {
    "target": "lomi_auth_test",
    "referenceOld": "lomi_auth_reference_old",
    "referenceNew": "lomi_auth_reference_new",
}
ROLE_SQL = """CREATE ROLE lomi_migrator LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE lomi_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
CREATE ROLE lomi_remote_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
CREATE ROLE lomi_remote_exchange LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
"""
RETIRED_SCALAR_SIGNATURES = (
    "public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)",
    "public.lomi_pairing_create_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb)",
    "public.lomi_pairing_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text)",
    "public.lomi_pairing_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid)",
    "public.lomi_grant_consumer_revoke(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,numeric)",
    "public.lomi_channel_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb)",
    "public.lomi_channel_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid)",
    "public.lomi_channel_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text)",
    "public.lomi_ticket_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb)",
    "public.lomi_ticket_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb,bytea)",
    "public.lomi_channel_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,jsonb,uuid)",
    "public.lomi_channel_peer_consumer_read(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,uuid)",
    "public.lomi_channel_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,text,uuid)",
    "public.lomi_ticket_consumer_prepare(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb,uuid)",
    "public.lomi_ticket_consumer_finalize(uuid,uuid,text,text,bigint,bigint,boolean,bytea,uuid,jsonb,bytea,uuid)",
)
V3_TABLES = (
    "public.consumer_authorization",
    "public.consumer_approval_intent",
    "public.consumer_approval_consumed_proof",
    "public.consumer_derivative_consent",
)
V3_OWNER_ROLES = (
    "lomi_remote_inventory_owner",
    "lomi_remote_pairing_write_owner",
    "lomi_consumer_auth_body_owner",
    "lomi_remote_runtime_owner",
)
EXCHANGE_PARENT_READ_COLUMNS = {
    "public.session_metadata": ["kind", "sessionId"],
    "public.remote_session_binding": ["accountId", "clientClass", "sessionId", "userId"],
    "public.remote_account_identity": ["authorizationEpoch", "id", "userId"],
}


class Rejected(RuntimeError):
    pass


class DeadlineExpired(Rejected):
    pass


S7_GROWTH_POLICY = {
    "version": 2,
    "unit": "unrelated-issued-principal-rows-per-kind",
    "targets": [1000, 10000],
    "kinds": ["remote_web", "mobile"],
    "dedicatedFixturesExcluded": 8,
    "minimumRelationRowsByTarget": {
        "1000": {
            "consumer_approval_intent": 2000,
            "consumer_derivative_consent": 2000,
            "remote_service_authorization": 2000,
            "remote_web_session": 1000,
            "mobile_session": 1000,
        },
        "10000": {
            "consumer_approval_intent": 20000,
            "consumer_derivative_consent": 20000,
            "remote_service_authorization": 20000,
            "remote_web_session": 10000,
            "mobile_session": 10000,
        },
    },
}

PLAN_STAGE_PURPOSES = [
    "Verify exact source closure, Homebrew PostgreSQL 18.6 and Bun dependency hashes/versions after two distinct source-bound receipts; establish marked private work and original deadline.",
    "Run pinned Prisma 7.10 migrate deploy against each private database, verify every private ledger row/checksum against pinned migration bytes, apply active operations, then compare exact old-source captures. This private fixture ledger is not production migration-history qualification.",
    "Install literal Consumer v3 sources in the target and source-derived new reference in reviewed order.",
    "Measure old/new root, helper, typed wrapper and product-channel catalogs from independent references; fill NULL spans only in private operator copies.",
    "Run helper seal, three-root and product-channel operators through all-old/all-new idempotency, mixed-state and drift-denial checks. Helper and root operators must reject real authentication-bypassing pg_proc body changes by exact P0001 guard reason and restore the complete catalog before positive controls. Run each owner-state subset at its measured phase; compare final target to reference-new.",
    "Measure effective role ACL positives/denials, exact host preservation and nine reviewed Exchange parent column grants. Require eighty sealed-helper denials as actual nonoperator logins, plus all twenty-eight owner-state rejection attempts executed at each operator's exact S4 phase after genuine positive controls; bound transcripts and complete catalog/role rollback must validate before PASS.",
    "Run pinned actual issuance/lifecycle/inventory/ACL and signed Host/Pairing/Channel/Ticket handler transactions with four explicit private URLs and four max-2 pools. Require both derivative kinds, fifteen typed overloads, owned heartbeat drain, exact operation recovery after lost ACK, uncertain ticket outcome without replay, and direct retained-key cleanup proof.",
    "Build unrelated issued principal rows through actual production flow primitives at T=1000 and T=10000: T remote-web plus T mobile rows (2T total) at each target, using the existing four private role pools. Require at least T in each kind-specific remote_web_session and mobile_session relation, and 2T in each shared consumer_approval_intent, consumer_derivative_consent, and remote_service_authorization relation. Add eight dedicated fixtures (two live pending plus six controls/tombstones) outside those unrelated populations. Require seven leading cascade lookup plans and three pending principal absence plans at both target sizes, five actual rollback DELETE/RI-trigger measurements at each target (ten total), two source-TTL deletion measurements retaining proof/consent/C and canonical liveness, real logout tombstones, unrelated controls, exact private receipt and raw-plan validation, and verified cleanup. This private stage does not qualify a real relay or physical phone/mobile/desktop clients.",
]

PLAN_BOUNDS = {
    "originalDeadlineSeconds": 900,
    "workDeadlineSeconds": 840,
    "cleanupDeadlineSeconds": 60,
    "postgresMaximumConnections": 16,
    "realRolePools": 4,
    "maximumConnectionsPerRolePool": 2,
    "stdoutBytesPerProcess": 1048576,
    "stderrBytesPerProcess": 1048576,
    "sqlCaptureBytes": 67108864,
    "bunEvidenceBytes": 1048576,
    "s7PrivateEvidenceBytes": 33554432,
    "s7DriverDeadlineSeconds": 360,
    "postgresSingleFileBytes": 67108864,
    "noTcpListeners": True,
    "productionQualifiedAlwaysFalse": True,
}

PLAN_LIMITS = [
    "No production connection or custom target option exists.",
    "The frozen v2 PostgreSQL runner and sealing runner are not imported or executed.",
    "S5 cannot pass from partial owner-state evidence, generic operator errors, absent positive controls or missing rollback/catalog preservation.",
    "S6 proves private handler transactions, not real relay or physical browser/mobile/desktop product acceptance.",
    "Any missing stage evidence remains NOT_RUN or FAILED and cannot produce PASS.",
    "A complete private run never authorizes deployment or production qualification.",
]


def _matches_exact_json(value, expected):
    """Compare JSON values without Python's bool/int equality ambiguity."""
    if type(expected) is dict:
        return (type(value) is dict and value.keys() == expected.keys()
                and all(_matches_exact_json(value[key], item) for key, item in expected.items()))
    if type(expected) is list:
        return (type(value) is list and len(value) == len(expected)
                and all(_matches_exact_json(actual, item) for actual, item in zip(value, expected)))
    return type(value) is type(expected) and value == expected


def validate_qualification_plan(plan):
    expected = {
        "schemaVersion": 2,
        "status": "PREPARED_NOT_ADMITTED",
        "admission": None,
        "productionQualified": False,
        "qualification": "NOT_RUN",
        "postgresTarget": "18.6",
        "bunTarget": "1.4.2",
        "executionBoundary": "SEPARATE_ROOT_AND_INDEPENDENT_REVIEW_RECEIPTS_REQUIRED",
        "sourceOnlyProhibition": {
            "postgresInvocations": 0,
            "sqlInvocations": 0,
            "databaseConnections": 0,
            "bunInvocations": 0,
            "operatorInvocations": 0,
            "candidateBuilderInvocations": 0,
            "networkInvocations": 0,
        },
        "s7GrowthPolicy": S7_GROWTH_POLICY,
        "stages": [
            {"id": f"S{number}", "status": "NOT_RUN", "purpose": purpose}
            for number, purpose in enumerate(PLAN_STAGE_PURPOSES)
        ],
        "bounds": PLAN_BOUNDS,
        "limits": PLAN_LIMITS,
    }
    if not _matches_exact_json(plan, expected):
        raise Rejected("bundle qualification plan does not match the closed v2 unadmitted contract")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_digest(path: Path) -> str:
    path = Path(path)
    if path.is_symlink():
        raise Rejected("expected regular source file")
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Rejected("expected regular source file")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
    finally:
        if fd >= 0:
            os.close(fd)
    return h.hexdigest()


def strict_json(raw: bytes, label: str):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise Rejected("invalid " + label) from error


def write_new(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def private_dir(path: Path, *, uid=None) -> None:
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or (uid is not None and info.st_uid != uid)):
        raise Rejected("private directory ownership or mode")


def safe_read(path: Path, *, max_bytes: int) -> bytes:
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Rejected("evidence path is not a regular file")
        if info.st_size > max_bytes:
            raise Rejected("evidence file exceeds byte limit")
        chunks = []
        size = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                raise Rejected("evidence file exceeds byte limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_local_modules():
    """Load only the exact adjacent pure validators; this has no execution side effects."""
    sys.path.insert(0, str(HERE))
    import admission  # noqa: E402
    import evidence  # noqa: E402
    import prepare  # noqa: E402
    return admission, evidence, prepare


def verify_bundle_data_before_import():
    """Verify every adjacent Python module as data before importing any of it."""
    if HERE.parent != PROJECT / "artifacts" or HERE.resolve() != HERE:
        raise Rejected("bundle must be a canonical direct private artifact child")
    if HERE.is_symlink() or stat.S_IMODE(HERE.lstat().st_mode) != 0o700 or HERE.lstat().st_uid != os.getuid():
        raise Rejected("bundle directory ownership or mode")
    for ancestor in HERE.parents:
        if ancestor.is_symlink():
            raise Rejected("bundle ancestry contains symlink")
    lock_raw = safe_read(HERE / "inputs.lock.json", max_bytes=2 * 1024 * 1024)
    lock = strict_json(lock_raw, "input lock")
    if (lock.get("schemaVersion") != 1
            or lock.get("status") != "SOURCE_LOCKED_NOT_ADMITTED"
            or lock.get("admission") != "TWO_DISTINCT_SOURCE_BOUND_INTEGRATOR_AND_REVIEWER_RECEIPTS_REQUIRED"
            or lock.get("productionQualified") is not False
            or lock.get("postgresVersion") != "18.6"
            or lock.get("bunVersion") != "1.4.2"):
        raise Rejected("source lock is not a private unadmitted closure")
    manifest_raw = safe_read(HERE / "bundle-manifest.json", max_bytes=4 * 1024 * 1024)
    manifest = strict_json(manifest_raw, "bundle manifest")
    plan_raw = safe_read(HERE / "plan.json", max_bytes=64 * 1024)
    plan = strict_json(plan_raw, "qualification plan")
    validate_qualification_plan(plan)
    source_pins = lock.get("sourceAllowlist")
    closed_trees = lock.get("closedTrees")
    if type(source_pins) is not dict or not source_pins or type(closed_trees) is not dict:
        raise Rejected("source lock allowlist or closed trees missing")
    contents = {}

    def checked_bytes(root: Path, relative: str, expected: str) -> bytes:
        if (type(relative) is not str or not relative or "\\" in relative
                or Path(relative).is_absolute()
                or any(part in ("", ".", "..") for part in Path(relative).parts)
                or type(expected) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise Rejected("source lock contains an unsafe path or digest")
        path = root
        for part in Path(relative).parts:
            path = path / part
            if path.is_symlink():
                raise Rejected("source closure traverses a symlink: " + relative)
        raw = safe_read(path, max_bytes=CATALOG_OUTPUT_LIMIT)
        if digest(raw) != expected:
            raise Rejected("source closure hash mismatch: " + relative)
        return raw

    for relative, expected in sorted(source_pins.items()):
        bundle_raw = checked_bytes(HERE / "inputs", relative, expected)
        workspace_raw = checked_bytes(WORKSPACE, relative, expected)
        if bundle_raw != workspace_raw:
            raise Rejected("bundle differs from current exact source: " + relative)
        contents[relative] = bundle_raw
    for tree_root, names in closed_trees.items():
        if (type(tree_root) is not str or not tree_root or "\\" in tree_root
                or Path(tree_root).is_absolute()
                or any(part in ("", ".", "..") for part in Path(tree_root).parts)
                or type(names) is not list or not names or len(names) != len(set(names))
                or any(type(name) is not str or not name.startswith(tree_root.rstrip("/") + "/")
                       or name not in source_pins for name in names)):
            raise Rejected("invalid source closed-tree entry")
        directory = WORKSPACE / tree_root
        if directory.is_symlink() or not directory.is_dir():
            raise Rejected("source closed-tree root missing")
        found = set()
        for item in directory.rglob("*"):
            if item.is_symlink():
                raise Rejected("workspace closed-tree symlink")
            if item.is_file():
                found.add(item.relative_to(WORKSPACE).as_posix())
        if found != set(names):
            raise Rejected("workspace source closed-tree membership drift")
    for relative in LOCAL_BUNDLE_FILES:
        raw = safe_read(HERE / relative, max_bytes=8 * 1024 * 1024)
        contents[relative] = raw
    expected_names = (set(LOCAL_BUNDLE_FILES) | {"bundle-manifest.json", "inputs.lock.json", "plan.json"}
                      | {"inputs/" + name for name in source_pins})
    found_names = set()
    for item in HERE.rglob("*"):
        if item.is_symlink():
            raise Rejected("prepared bundle contains symlink")
        if item.is_file():
            found_names.add(item.relative_to(HERE).as_posix())
    optional_receipts = {"admission/independent-review.json", "admission/root-admission.json"}
    if not expected_names <= found_names or found_names - expected_names - optional_receipts:
        raise Rejected("prepared source bundle membership drift")
    for name, raw in contents.items():
        if manifest.get("sourceFiles", {}).get(name) != digest(raw):
            raise Rejected("prepared manifest local/source hash mismatch: " + name)
    for name in source_pins:
        if manifest.get("sourceFiles", {}).get(name) != digest(contents[name]):
            raise Rejected("prepared manifest input hash mismatch: " + name)
    if (manifest.get("status") != "PREPARED_NOT_ADMITTED"
            or manifest.get("admission") is not None
            or manifest.get("productionQualified") is not False
            or manifest.get("qualification") != "NOT_RUN"
            or manifest.get("stages") != {f"S{i}": "NOT_RUN" for i in range(8)}
            or manifest.get("inputsLockSha256") != digest(lock_raw)
            or manifest.get("planSha256") != digest(plan_raw)
            or manifest.get("controllerSha256") != digest(contents["controller.py"])
            or manifest.get("sourceFiles") != {name: digest(raw) for name, raw in sorted(contents.items())}
            or manifest.get("postgresFiles") != lock.get("postgresFiles")
            or manifest.get("bunSha256") != lock.get("bunSha256")):
        raise Rejected("prepared bundle manifest does not close exact local and input sources")
    return lock, manifest, digest(contents["controller.py"]), digest(manifest_raw)


def checked_package_validator():
    package = PACKAGE.resolve(strict=True)
    if not package.is_dir() or package.is_symlink():
        raise Rejected("successor package path")
    source_manifest = safe_read(package / "source-manifest.json", max_bytes=2 * 1024 * 1024)
    lock = strict_json(safe_read(HERE / "inputs.lock.json", max_bytes=2 * 1024 * 1024), "input lock")
    if digest(source_manifest) != lock.get("successorManifestSha256"):
        raise Rejected("successor source manifest hash drift")
    sys.path.insert(0, str(package))
    spec = importlib.util.spec_from_file_location("consumer_v3_successor_validator", package / "validate_successor.py")
    if spec is None or spec.loader is None:
        raise Rejected("successor validator import failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors = module.validate_workspace()
    if errors:
        raise Rejected("successor package static validator failed: " + str(errors[0]))
    return {"sourceManifestSha256": digest(source_manifest), "staticValidator": "PASS"}


def verify_bundle_and_receipts():
    lock, manifest, controller_sha, manifest_sha = verify_bundle_data_before_import()
    admission, evidence, prepare = load_local_modules()
    manifest_path = HERE / "bundle-manifest.json"
    manifest_raw = safe_read(manifest_path, max_bytes=4 * 1024 * 1024)
    checked_manifest = prepare.validate_bundle(HERE)
    if checked_manifest != manifest or controller_sha != manifest.get("controllerSha256"):
        raise Rejected("prepared controller hash mismatch")
    if manifest.get("status") != "PREPARED_NOT_ADMITTED" or manifest.get("productionQualified") is not False:
        raise Rejected("bundle must remain unadmitted and unqualified")
    artifact_root = PROJECT / "artifacts"
    if HERE.parent != artifact_root or HERE.resolve() != HERE:
        raise Rejected("bundle must be a canonical direct private artifact child")
    for ancestor in (HERE, *HERE.parents):
        if ancestor.is_symlink():
            raise Rejected("bundle ancestry contains symlink")
    private_dir(HERE, uid=os.getuid())
    admission_dir = HERE / "admission"
    private_dir(admission_dir, uid=os.getuid())
    allowed = {"independent-review.json", "root-admission.json"}
    entries = set(os.listdir(admission_dir))
    if entries != allowed:
        raise Rejected("both exact local admission receipts are required")
    for name in allowed:
        path = admission_dir / name
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid()):
            raise Rejected("admission receipt ownership or mode")
    independent_raw = safe_read(admission_dir / "independent-review.json", max_bytes=64 * 1024)
    root_raw = safe_read(admission_dir / "root-admission.json", max_bytes=64 * 1024)
    receipts = admission.validate_receipts(
        root_raw,
        independent_raw,
        controller_sha256=controller_sha,
        manifest_sha256=manifest_sha,
    )
    return lock, manifest, controller_sha, manifest_sha, receipts, evidence, prepare


def dependency_tree_digest(root: Path, expected_links: dict[str, str]) -> str:
    """Hash every dependency entry; reject added/removed files and unpinned symlinks."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise Rejected("runtime dependency tree missing")
    seen_links = {}
    entries = []
    for item in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        rel = item.relative_to(root).as_posix()
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(item)
            if rel not in expected_links or expected_links[rel] != target:
                raise Rejected("unapproved runtime dependency symlink")
            seen_links[rel] = target
            entries.append((rel, "link", target))
        elif stat.S_ISREG(info.st_mode):
            entries.append((rel, "file", file_digest(item)))
        elif not stat.S_ISDIR(info.st_mode):
            raise Rejected("special runtime dependency entry")
    if seen_links != expected_links:
        raise Rejected("runtime dependency symlink closure drift")
    encoded = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return digest(encoded)


def verify_toolchain(lock: dict) -> dict:
    pg_root = Path(lock.get("postgresRoot", ""))
    if (not pg_root.is_absolute() or pg_root.resolve() != pg_root
            or str(pg_root) != "/opt/homebrew/Cellar/postgresql@18/18.6_1"):
        raise Rejected("canonical Homebrew PostgreSQL 18.6 root required")
    alias_path = Path(lock.get("postgresAliasPath", ""))
    alias_target = lock.get("postgresAliasTarget")
    if (str(alias_path) != "/opt/homebrew/opt/postgresql@18"
            or type(alias_target) is not str or not alias_path.is_symlink()
            or os.readlink(alias_path) != alias_target
            or alias_path.resolve(strict=True) != pg_root):
        raise Rejected("PostgreSQL 18.6 Homebrew alias drift")
    pg_hashes = lock.get("postgresFiles")
    pg_links = lock.get("postgresSymlinks")
    if type(pg_hashes) is not dict or len(pg_hashes) < 3000 or type(pg_links) is not dict:
        raise Rejected("exact PostgreSQL 18.6 tool closure required")
    actual = {}
    for relative, expected in sorted(pg_hashes.items()):
        if (type(relative) is not str or relative.startswith("/")
                or any(part in ("", ".", "..") for part in Path(relative).parts)):
            raise Rejected("unsafe PostgreSQL closure path")
        actual[relative] = file_digest(pg_root / relative)
        if actual[relative] != expected:
            raise Rejected("PostgreSQL tool closure hash drift")
    actual_links = {}
    for relative, expected_target in sorted(pg_links.items()):
        if (type(relative) is not str or relative.startswith("/")
                or any(part in ("", ".", "..") for part in Path(relative).parts)):
            raise Rejected("unsafe PostgreSQL symlink closure path")
        link = pg_root / relative
        if not link.is_symlink():
            raise Rejected("PostgreSQL symlink closure drift")
        actual_links[relative] = os.readlink(link)
        if actual_links[relative] != expected_target:
            raise Rejected("PostgreSQL symlink target drift")
    found_files = set()
    found_links = set()
    for item in pg_root.rglob("*"):
        relative = item.relative_to(pg_root).as_posix()
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            found_links.add(relative)
        elif stat.S_ISREG(info.st_mode):
            found_files.add(relative)
        elif not stat.S_ISDIR(info.st_mode):
            raise Rejected("special entry in PostgreSQL installation tree")
    if found_files != set(pg_hashes) or found_links != set(pg_links):
        raise Rejected("PostgreSQL installation tree entry closure drift")
    required = {"bin/initdb", "bin/postgres", "bin/pg_ctl", "bin/psql"}
    if not required <= set(pg_hashes):
        raise Rejected("required PostgreSQL executables are outside pinned closure")

    dependencies = lock.get("postgresDependencies")
    dependency_aliases = lock.get("postgresDependencyAliases")
    dependency_alias_targets = lock.get("postgresDependencyAliasTargets")
    if (type(dependencies) is not dict or type(dependency_aliases) is not dict
            or not dependencies or type(dependency_alias_targets) is not dict):
        raise Rejected("PostgreSQL transitive dynamic-library closure required")
    actual_dependencies = {}
    for absolute, expected in sorted(dependencies.items()):
        path = Path(absolute)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise Rejected("PostgreSQL dependency path is not canonical")
        actual_dependencies[absolute] = file_digest(path)
        if actual_dependencies[absolute] != expected:
            raise Rejected("PostgreSQL dynamic-library dependency drift")
    for alias, canonical in dependency_aliases.items():
        path = Path(alias)
        if (not path.is_absolute() or type(canonical) is not str
                or path.resolve(strict=True) != Path(canonical)):
            raise Rejected("PostgreSQL dynamic-library alias drift")
    for alias, target in dependency_alias_targets.items():
        path = Path(alias)
        if (not path.is_absolute() or type(target) is not str or not path.is_symlink()
                or os.readlink(path) != target):
            raise Rejected("PostgreSQL dynamic-library symlink target drift")

    formulas = lock.get("postgresFormulaAliases")
    if type(formulas) is not dict:
        raise Rejected("PostgreSQL dependency formula alias closure required")
    for alias, entry in formulas.items():
        path = Path(alias)
        if (not path.is_absolute() or type(entry) is not dict
                or not path.is_symlink() or os.readlink(path) != entry.get("target")
                or path.resolve(strict=True) != Path(entry.get("resolved", ""))):
            raise Rejected("Homebrew dependency formula alias drift")

    host_platform = lock.get("hostPlatform")
    if host_platform != {"macVersion": platform.mac_ver()[0], "machine": platform.machine()}:
        raise Rejected("macOS system dynamic-library platform drift")
    system_dependencies = lock.get("systemDependencies")
    if type(system_dependencies) is not dict or not system_dependencies:
        raise Rejected("macOS system-library load-command closure required")
    for path, versions in system_dependencies.items():
        if (not (path.startswith("/usr/lib/") or path.startswith("/System/Library/"))
                or type(versions) is not list or not versions
                or any(type(item) is not dict
                       or set(item) != {"compatibilityVersion", "currentVersion"}
                       or any(type(value) is not str or not re.fullmatch(r"[0-9.]+", value)
                              for value in item.values())
                       for item in versions)):
            raise Rejected("invalid macOS system-library load-command entry")
    for field in ("postgresLoadCommands", "bunLoadCommands"):
        if type(lock.get(field)) is not dict or not lock[field]:
            raise Rejected("dynamic-library load-command manifest missing")
        expected = lock.get(field + "Sha256")
        actual_sha = digest(json.dumps(lock[field], sort_keys=True, separators=(",", ":")).encode())
        if expected != actual_sha:
            raise Rejected("dynamic-library load-command manifest hash drift")

    if (Path(lock.get("bunPath", "")) != BUN_PATH
            or Path(lock.get("bunCanonicalPath", "")) != BUN_CANONICAL_PATH
            or lock.get("bunSha256") != BUN_SHA256):
        raise Rejected("pinned Bun 1.4.2 path or binary hash drift")
    bun = BUN_PATH
    if bun.resolve(strict=True) != BUN_CANONICAL_PATH:
        raise Rejected("Bun path canonicalization drift")
    bun_sha = file_digest(bun)
    if bun_sha != lock.get("bunSha256"):
        raise Rejected("Bun binary hash drift")
    bun_dependencies = lock.get("bunDependencies")
    bun_aliases = lock.get("bunDependencyAliases")
    bun_alias_targets = lock.get("bunDependencyAliasTargets")
    if (type(bun_dependencies) is not dict or type(bun_aliases) is not dict
            or type(bun_alias_targets) is not dict):
        raise Rejected("Bun dynamic-library closure required")
    for absolute, expected in bun_dependencies.items():
        path = Path(absolute)
        if not path.is_absolute() or path.resolve(strict=True) != path or file_digest(path) != expected:
            raise Rejected("Bun dynamic-library dependency drift")
    for alias, canonical in bun_aliases.items():
        path = Path(alias)
        if (not path.is_absolute() or type(canonical) is not str
                or path.resolve(strict=True) != Path(canonical)):
            raise Rejected("Bun dynamic-library alias drift")
    for alias, target in bun_alias_targets.items():
        path = Path(alias)
        if (not path.is_absolute() or type(target) is not str or not path.is_symlink()
                or os.readlink(path) != target):
            raise Rejected("Bun dynamic-library symlink target drift")
    package_json = safe_read(AUTH / "package.json", max_bytes=1024 * 1024)
    package = strict_json(package_json, "Auth package.json")
    versions = {
        **package.get("dependencies", {}),
        **package.get("devDependencies", {}),
        **package.get("overrides", {}),
    }
    for name, version in lock.get("dependencyVersions", {}).items():
        if versions.get(name) != version:
            raise Rejected("locked Auth dependency version drift")
    tree_sha = dependency_tree_digest(WORKSPACE / "auth-app/node_modules", lock.get("runtimeDependencySymlinks", {}))
    if tree_sha != lock.get("runtimeDependencyTreeSha256"):
        raise Rejected("Auth runtime dependency tree hash drift")
    if (lock.get("prismaCliPath") != str(PRISMA_CLI_PATH)
            or lock.get("prismaCliSha256") != PRISMA_CLI_SHA256
            or lock.get("prismaSchemaEnginePath") != str(PRISMA_SCHEMA_ENGINE_PATH)
            or lock.get("prismaSchemaEngineSha256") != PRISMA_SCHEMA_ENGINE_SHA256):
        raise Rejected("pinned Prisma 7.10 CLI or schema-engine identity drift")
    prisma_cli_sha = file_digest(PRISMA_CLI_PATH)
    prisma_engine_sha = file_digest(PRISMA_SCHEMA_ENGINE_PATH)
    if (prisma_cli_sha != lock["prismaCliSha256"]
            or prisma_engine_sha != lock["prismaSchemaEngineSha256"]):
        raise Rejected("pinned Prisma 7.10 CLI or schema-engine hash drift")
    return {"postgresFiles": actual, "postgresSymlinks": actual_links,
            "postgresDependencies": actual_dependencies, "bunSha256": bun_sha,
            "runtimeDependencyTreeSha256": tree_sha,
            "prismaCliSha256": prisma_cli_sha,
            "prismaSchemaEngineSha256": prisma_engine_sha}


class BoundedProcess:
    def __init__(self, owned, *, env: dict[str, str], work: Path, started: float,
                 work_deadline: float, final_deadline: float, run_dir: Path):
        self.owned = owned
        self.env = env
        self.work = work
        self.started = started
        self.work_deadline = work_deadline
        self.final_deadline = final_deadline
        self.run_dir = run_dir
        self.serial = 0
        self.records = []

    def remaining(self, cleanup=False):
        deadline = self.final_deadline if cleanup else self.work_deadline
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExpired("original fixture deadline expired")
        return remaining

    def command(self, label: str, argv: list[str], *, timeout=120,
                output_limit=PROCESS_OUTPUT_LIMIT, stdout_file: Path | None = None,
                expected=(0,), input_file: Path | None = None,
                cleanup=False, cwd: Path | None = None,
                env: dict[str, str] | None = None) -> dict:
        self.owned.require_process_ownership()
        left = self.remaining(cleanup)
        timeout = min(timeout, left)
        if not argv or not Path(argv[0]).is_absolute():
            raise Rejected("command requires a pinned absolute executable")
        self.serial += 1
        stem = f"command-{self.serial:03d}-{re.sub('[^a-z0-9-]+', '-', label.lower()).strip('-')[:48]}"
        stdout_path = stdout_file or (self.run_dir / (stem + ".stdout"))
        stderr_path = self.run_dir / (stem + ".stderr")
        for path in (stdout_path, stderr_path):
            if path.exists() or path.is_symlink():
                raise Rejected("command evidence path already exists")
        out_fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        err_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        input_stream = None
        child = None
        selector = None
        try:
            if input_file is not None:
                input_stream = input_file.open("rb")

            def limit_child_files():
                # PostgreSQL owns data/WAL files up to the explicitly admitted
                # 64 MiB single-file ceiling. stdout/stderr are separate pipes
                # drained and capped by this parent process below.
                resource.setrlimit(resource.RLIMIT_FSIZE, (PROCESS_FILE_LIMIT, PROCESS_FILE_LIMIT))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

            child = subprocess.Popen(
                argv,
                cwd=self.work if cwd is None else cwd,
                env=self.env if env is None else env,
                stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
                preexec_fn=limit_child_files,
            )
            os.set_blocking(child.stdout.fileno(), False)
            os.set_blocking(child.stderr.fileno(), False)
            selector = selectors.DefaultSelector()
            selector.register(child.stdout, selectors.EVENT_READ, "stdout")
            selector.register(child.stderr, selectors.EVENT_READ, "stderr")
            byte_counts = {"stdout": 0, "stderr": 0}
            streams = {"stdout": out_fd, "stderr": err_fd}
            deadline = time.monotonic() + timeout
            exited_at = None
            while True:
                if exited_at is None:
                    try:
                        state = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    except ChildProcessError as error:
                        raise Rejected("owned process identity was reaped early") from error
                    if state is not None:
                        code = child.wait(timeout=1)
                        exited_at = time.monotonic()
                if exited_at is None and time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(argv, timeout)
                ready = selector.select(0.05 if exited_at is None else 0.01)
                for key, _ in ready:
                    label_name = key.data
                    try:
                        chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    limit = output_limit if label_name == "stdout" else PROCESS_OUTPUT_LIMIT
                    if byte_counts[label_name] + len(chunk) > limit:
                        raise Rejected("command output exceeded fixed byte ceiling")
                    offset = 0
                    while offset < len(chunk):
                        offset += os.write(streams[label_name], chunk[offset:])
                    byte_counts[label_name] += len(chunk)
                if exited_at is not None:
                    # Children may close inherited output pipes after exit.
                    # Drain currently ready bytes, then stop waiting for any
                    # detached writer; process-group cleanup remains owned.
                    if not ready or not selector.get_map():
                        break
                    if time.monotonic() - exited_at > 0.25:
                        break
            selector.close()
            selector = None
            child.stdout.close()
            child.stderr.close()
            os.close(out_fd); out_fd = -1
            os.close(err_fd); err_fd = -1
            stdout_info = stdout_path.stat()
            stderr_info = stderr_path.stat()
            if stdout_info.st_size > output_limit or stderr_info.st_size > PROCESS_OUTPUT_LIMIT:
                raise Rejected("command output exceeded fixed byte ceiling")
            stdout_raw = safe_read(stdout_path, max_bytes=output_limit)
            stderr_raw = safe_read(stderr_path, max_bytes=PROCESS_OUTPUT_LIMIT)
            if code not in expected:
                detail = (stderr_raw + b"\n" + stdout_raw).decode("utf-8", "replace")[-3000:]
                raise Rejected("command failed (" + label + "): " + detail)
            result = {
                "label": label,
                "returnCode": code,
                "stdoutPath": stdout_path.name,
                "stdoutBytes": len(stdout_raw),
                "stdoutSha256": digest(stdout_raw),
                "stderrPath": stderr_path.name,
                "stderrBytes": len(stderr_raw),
                "stderrSha256": digest(stderr_raw),
            }
            self.records.append(result)
            return {**result, "stdout": stdout_raw, "stderr": stderr_raw}
        except BaseException:
            if child is not None and child.returncode is None:
                try:
                    self.owned.stop_group(child)
                except BaseException:
                    # The outer fixture cleanup retains the marker and refuses
                    # recursive disposal when process ownership is uncertain.
                    pass
            raise
        finally:
            if selector is not None:
                selector.close()
            if input_stream is not None:
                input_stream.close()
            if child is not None:
                for stream in (child.stdout, child.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
            if out_fd >= 0:
                os.close(out_fd)
            if err_fd >= 0:
                os.close(err_fd)


def private_environment(work: Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PGHOST": str(work / "socket"),
        "PGPORT": PORT,
        "PGUSER": "e2_owner",
        "PGDATABASE": "postgres",
        "PGPASSFILE": str(work / "home/pgpass-empty"),
        "PGSERVICEFILE": str(work / "home/pg_service.conf.empty"),
        "PGOPTIONS": "-c statement_timeout=55000 -c lock_timeout=10000 -c idle_in_transaction_session_timeout=55000",
        "PAGER": "cat",
        "NO_COLOR": "1",
    }


def prisma_migration_source_paths(source_allowlist: dict) -> tuple[str, ...]:
    required = {
        "auth-app/package.json",
        "auth-app/bun.lock",
        "auth-app/prisma.config.ts",
        "auth-app/prisma/schema.prisma",
        "auth-app/prisma/migrations/migration_lock.toml",
    }
    if type(source_allowlist) is not dict or not required <= set(source_allowlist):
        raise Rejected("pinned Prisma project inputs are incomplete")
    migrations = sorted(
        name for name in source_allowlist
        if type(name) is str
        and re.fullmatch(r"auth-app/prisma/migrations/[^/]+/migration\.sql", name)
    )
    if (not migrations
            or not any("/202610220012_" in name for name in migrations)
            or not any("/202610220013_" in name for name in migrations)):
        raise Rejected("pinned Prisma migration closure must include 202610220012 and 202610220013")
    names = [Path(name).parent.name for name in migrations]
    if len(names) != len(set(names)):
        raise Rejected("pinned Prisma migration names are not unique")
    return tuple(sorted(required | set(migrations)))


def validate_prisma_config_source(raw: bytes) -> dict[str, str]:
    try:
        source = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise Rejected("pinned Prisma config is not UTF-8") from error
    env_names = re.findall(r"\benv\(\s*['\"]([^'\"]+)['\"]\s*\)", source)
    if (env_names != ["MIGRATION_DATABASE_URL"]
            or re.search(r"\b(?:process|Bun)\.env\b", source)
            or not re.search(r"schema\s*:\s*['\"]prisma/schema\.prisma['\"]", source)
            or not re.search(r"migrations\s*:\s*\{\s*path\s*:\s*['\"]prisma/migrations['\"]\s*\}", source)):
        raise Rejected("pinned Prisma config must use only the private migration URL and pinned schema tree")
    return {"schema": "prisma/schema.prisma", "migrations": "prisma/migrations",
            "databaseUrlVariable": "MIGRATION_DATABASE_URL"}


def prisma_expected_migrations(source_bytes: dict[str, bytes]) -> list[dict]:
    rows = []
    for relative, raw in sorted(source_bytes.items()):
        if not re.fullmatch(r"auth-app/prisma/migrations/[^/]+/migration\.sql", relative):
            continue
        if type(raw) is not bytes:
            raise Rejected("pinned Prisma migration input is not bytes")
        rows.append({"migrationName": Path(relative).parent.name, "checksum": digest(raw)})
    if (not rows
            or not any(item["migrationName"].startswith("202610220012_") for item in rows)
            or not any(item["migrationName"].startswith("202610220013_") for item in rows)):
        raise Rejected("expected Prisma ledger set omits active migration 202610220012 or 202610220013")
    if len({item["migrationName"] for item in rows}) != len(rows):
        raise Rejected("expected Prisma ledger contains duplicate migration names")
    return rows


def validate_prisma_migration_ledger(raw: bytes, expected_rows: list[dict]) -> list[dict]:
    if type(raw) is not bytes or not raw:
        raise Rejected("private Prisma migration ledger capture is empty")
    actual = []
    for line in raw.splitlines():
        if not line:
            continue
        row = strict_json(line, "private Prisma migration ledger row")
        if (type(row) is not dict
                or set(row) != {"migrationName", "checksum", "finishedAt", "rolledBackAt"}
                or type(row.get("migrationName")) is not str
                or type(row.get("checksum")) is not str
                or type(row.get("finishedAt")) is not str or not row["finishedAt"]
                or row.get("rolledBackAt") is not None):
            raise Rejected("private Prisma migration ledger has unfinished, rolled-back or malformed rows")
        actual.append(row)
    expected = [
        {"migrationName": row["migrationName"], "checksum": row["checksum"]}
        for row in expected_rows
    ]
    actual_pairs = [{"migrationName": row["migrationName"], "checksum": row["checksum"]}
                    for row in actual]
    if (actual_pairs != expected
            or len({row["migrationName"] for row in actual}) != len(actual)):
        raise Rejected("private Prisma ledger rows or source checksums differ from pinned migrations")
    return actual


def prisma_migration_url(database: str, socket_path: str) -> str:
    if database not in DATABASES.values():
        raise Rejected("Prisma migration database is outside the private fixture")
    match = (re.fullmatch(r"/tmp/lomi-e2-([0-9a-f-]{36})/socket", socket_path)
             if type(socket_path) is str else None)
    try:
        canonical_uuid = str(uuid.UUID(match.group(1))) if match else None
    except ValueError:
        canonical_uuid = None
    if not match or canonical_uuid != match.group(1):
        raise Rejected("Prisma migration URL requires the marked private socket")
    return (f"postgresql://lomi_migrator@localhost:{PORT}/{database}?"
            + urlencode([("host", socket_path)]))


def prisma_migration_environment(work: Path, database: str, socket_path: str,
                                 engine_path: Path) -> dict[str, str]:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PGPORT": PORT,
        "PGPASSFILE": str(work / "home/pgpass-empty"),
        "PGSERVICEFILE": str(work / "home/pg_service.conf.empty"),
        "PGOPTIONS": "-c statement_timeout=55000 -c lock_timeout=10000 -c idle_in_transaction_session_timeout=55000",
        "MIGRATION_DATABASE_URL": prisma_migration_url(database, socket_path),
        "PRISMA_SCHEMA_ENGINE_BINARY": str(engine_path),
        "JITI_FS_CACHE": "0",
        "CHECKPOINT_DISABLE": "1",
        "PRISMA_HIDE_UPDATE_MESSAGE": "1",
    }
    validate_prisma_migration_environment(env, work, database, socket_path, engine_path)
    return env


def validate_prisma_migration_environment(env: dict[str, str], work: Path,
                                           database: str, socket_path: str,
                                           engine_path: Path) -> None:
    expected = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PGPORT": PORT,
        "PGPASSFILE": str(work / "home/pgpass-empty"),
        "PGSERVICEFILE": str(work / "home/pg_service.conf.empty"),
        "PGOPTIONS": "-c statement_timeout=55000 -c lock_timeout=10000 -c idle_in_transaction_session_timeout=55000",
        "MIGRATION_DATABASE_URL": prisma_migration_url(database, socket_path),
        "PRISMA_SCHEMA_ENGINE_BINARY": str(engine_path),
        "JITI_FS_CACHE": "0",
        "CHECKPOINT_DISABLE": "1",
        "PRISMA_HIDE_UPDATE_MESSAGE": "1",
    }
    if type(env) is not dict or env != expected:
        raise Rejected("Prisma migration process environment differs from its private allowlist")
    try:
        parsed = urlsplit(env["MIGRATION_DATABASE_URL"])
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        port = parsed.port
    except (ValueError, UnicodeError) as error:
        raise Rejected("Prisma migration URL is malformed") from error
    if (parsed.scheme != "postgresql" or parsed.username != "lomi_migrator"
            or parsed.password is not None or parsed.hostname != "localhost"
            or port != int(PORT) or parsed.path != "/" + database
            or parsed.fragment or query != [("host", socket_path)]):
        raise Rejected("Prisma migration URL does not bind the owned socket and database")


def prisma_migration_argv(bun_path: Path) -> list[str]:
    if Path(bun_path) != BUN_PATH:
        raise Rejected("Prisma migration requires the pinned Bun executable")
    return [str(bun_path), "--no-env-file", "node_modules/prisma/build/index.js",
            "migrate", "deploy", "--config", "prisma.config.ts"]


def validate_prisma_project_tree(project: Path, source_hashes: dict[str, str],
                                 dependency_target: str, *, require_complete: bool) -> None:
    project = Path(project)
    if project.is_symlink() or not project.is_dir():
        raise Rejected("private Prisma project directory identity mismatch")
    expected_links = {"node_modules": dependency_target} if source_hashes else {}
    expected_files = {name: sha for name, sha in source_hashes.items()}
    seen_files = {}
    seen_links = {}
    seen_directories = set()
    for item in sorted(project.rglob("*"), key=lambda path: path.relative_to(project).as_posix()):
        relative = item.relative_to(project).as_posix()
        info = item.lstat()
        if info.st_uid != os.getuid():
            raise Rejected("private Prisma project contains an unowned entry")
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(item)
            if relative != "node_modules" or target != dependency_target:
                raise Rejected("private Prisma project contains an unapproved dependency link")
            seen_links[relative] = target
        elif stat.S_ISDIR(info.st_mode):
            if stat.S_IMODE(info.st_mode) != 0o700:
                raise Rejected("private Prisma project directory mode drift")
            seen_directories.add(relative)
        elif stat.S_ISREG(info.st_mode):
            if relative not in expected_files:
                raise Rejected("private Prisma project contains an unpinned file")
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise Rejected("private Prisma project source file mode drift")
            if file_digest(item) != expected_files[relative]:
                raise Rejected("private Prisma project source hash drift")
            seen_files[relative] = expected_files[relative]
        else:
            raise Rejected("private Prisma project contains a special entry")
    expected_files_set = set(expected_files)
    if require_complete and set(seen_files) != expected_files_set:
        raise Rejected("private Prisma project source file closure is incomplete")
    if set(seen_files) != expected_files_set & set(seen_files):
        raise Rejected("private Prisma project contains an unexpected source")
    if require_complete and seen_links != expected_links:
        raise Rejected("private Prisma project dependency link closure is incomplete")
    if set(seen_links) - set(expected_links):
        raise Rejected("private Prisma project dependency link closure drift")
    expected_directories = {
        parent.as_posix()
        for name in seen_files
        for parent in Path(name).parents
        if parent.as_posix() != "."
    }
    if seen_directories != expected_directories:
        raise Rejected("private Prisma project directory closure drift")


def catalog_operator_environment(base: dict[str, str]) -> dict[str, str]:
    """Keep PostgreSQL operator deparsing aligned with capture.sql."""
    result = dict(base)
    result["PGOPTIONS"] = result["PGOPTIONS"] + " -c search_path=pg_catalog"
    return result


def write_private_marker(work: Path, *, run_id: str, bundle_manifest_sha: str) -> dict:
    marker = {
        "schemaVersion": 1,
        "runId": run_id,
        "bundleManifestSha256": bundle_manifest_sha,
        "dataDirectory": str(work / "data"),
        "socketDirectory": str(work / "socket"),
        "homeDirectory": str(work / "home"),
        "tempDirectory": str(work / "tmp"),
        "sqlDirectory": str(work / "sql"),
        "bunProjectDirectory": str(work / "bun-project"),
        "prismaProjectDirectory": str(work / PRISMA_PROJECT_CHILD),
        "s7SourceDirectory": str(work / "s7-sources"),
        "s7PlanFile": str(work / "s7-plan.json"),
        "s7OutputFile": str(work / "s7-output.json"),
        "runtimeDependencyLink": str(WORKSPACE / "auth-app/node_modules"),
        "prismaDependencyLink": str(WORKSPACE / "auth-app/node_modules"),
        "databaseNames": DATABASES,
        "productionTarget": False,
    }
    write_new(work / "fixture.marker.json", (json.dumps(marker, sort_keys=True, indent=2) + "\n").encode())
    return marker


def validate_work_marker(work: Path, expected: dict) -> None:
    private_dir(work, uid=os.getuid())
    raw = safe_read(work / "fixture.marker.json", max_bytes=64 * 1024)
    actual = strict_json(raw, "fixture marker")
    if actual != expected:
        raise Rejected("fixture cleanup marker identity mismatch")
    if str(work) != expected["socketDirectory"].removesuffix("/socket"):
        raise Rejected("fixture work path does not match socket marker")
    for name in ("data", "socket", "home", "tmp", "sql", "bun-project", PRISMA_PROJECT_CHILD):
        child = work / name
        if child.is_symlink() or not child.is_dir():
            raise Rejected("fixture child directory identity mismatch")
        if stat.S_IMODE(child.stat().st_mode) != 0o700 or child.stat().st_uid != os.getuid():
            raise Rejected("fixture child directory mode or owner")
    for name, field in (("s7-sources", "s7SourceDirectory"),
                        ("s7-plan.json", "s7PlanFile"),
                        ("s7-output.json", "s7OutputFile")):
        if expected.get(field) != str(work / name):
            raise Rejected("S7 cleanup path differs from the original marker")


def source_input(relative: str) -> Path:
    path = HERE / "inputs" / relative
    if path.is_symlink() or not path.is_file():
        raise Rejected("bundled input missing: " + relative)
    return path


def write_work_source(work: Path, name: str, raw: bytes) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", name):
        raise Rejected("unsafe generated SQL filename")
    path = work / "sql" / name
    write_new(path, raw)
    return path


def literal_operator_definitions(raw: bytes, count: int, expected_names: tuple[str, ...]) -> list[bytes]:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise Rejected("operator source is not UTF-8") from error
    definitions = []
    for index in range(count):
        tag = f"$literal{index}$"
        marker = f"EXECUTE {tag}"
        if text.count(marker) != 1 or text.count(tag) != 2:
            raise Rejected("literal operator statement closure drift")
        start = text.index(marker) + len(marker)
        end = text.index(tag, start)
        definition = text[start:end].strip()
        expected = "CREATE OR REPLACE FUNCTION public." + expected_names[index] + "("
        if not definition.startswith(expected) or not definition.endswith(";"):
            raise Rejected("literal operator definition order drift")
        definitions.append(definition.encode("utf-8"))
    return definitions


def json_sql(value) -> str:
    return "'" + json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace("'", "''") + "'::jsonb"


def s6_urls(socket_path: str) -> dict[str, str]:
    return {
        "LOMI_E2_PRIVATE_OWNER_URL": f"postgresql://e2_owner@localhost/{DATABASES['target']}?host={socket_path}",
        "LOMI_E2_PRIVATE_RUNTIME_URL": f"postgresql://lomi_runtime@localhost/{DATABASES['target']}?host={socket_path}",
        "LOMI_E2_PRIVATE_REMOTE_URL": f"postgresql://lomi_remote_api@localhost/{DATABASES['target']}?host={socket_path}",
        "LOMI_E2_PRIVATE_EXCHANGE_URL": f"postgresql://lomi_remote_exchange@localhost/{DATABASES['target']}?host={socket_path}",
    }


S6_URL_ROLES = {
    "LOMI_E2_PRIVATE_OWNER_URL": "e2_owner",
    "LOMI_E2_PRIVATE_RUNTIME_URL": "lomi_runtime",
    "LOMI_E2_PRIVATE_REMOTE_URL": "lomi_remote_api",
    "LOMI_E2_PRIVATE_EXCHANGE_URL": "lomi_remote_exchange",
}


def validate_s6_private_environment(env: dict[str, str], socket_path: str) -> None:
    expected_keys = {
        "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "TERM",
        "BUN_CONFIG_NO_CLEAR_TERMINAL", "LOMI_E2_CONSUMER_DERIVATIVE_PRODUCT_RUNTIME",
        "PGPORT", *S6_URL_ROLES,
    }
    if type(env) is not dict or set(env) != expected_keys:
        raise Rejected("S6 environment is not the exact private socket contract")
    if env.get("PGPORT") != PORT:
        raise Rejected("S6 PGPORT does not target the owned private PostgreSQL server")
    if (env.get("PATH") != "/usr/bin:/bin"
            or env.get("LOMI_E2_CONSUMER_DERIVATIVE_PRODUCT_RUNTIME") != "true"
            or env.get("BUN_CONFIG_NO_CLEAR_TERMINAL") != "1"):
        raise Rejected("S6 runtime environment selector or executable path drift")
    for variable, role in S6_URL_ROLES.items():
        try:
            parsed = urlsplit(env[variable])
            query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
            port = parsed.port
        except (ValueError, UnicodeError) as error:
            raise Rejected("S6 role URL is malformed") from error
        if (parsed.scheme not in ("postgres", "postgresql")
                or parsed.username != role or parsed.password is not None
                or parsed.hostname != "localhost" or port is not None
                or parsed.path != "/" + DATABASES["target"] or parsed.fragment
                or query != [("host", socket_path)]):
            raise Rejected("S6 role URL must use the owned database and one private socket")


def s6_private_environment(work: Path, socket_path: str) -> dict[str, str]:
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TERM": "dumb",
        "BUN_CONFIG_NO_CLEAR_TERMINAL": "1",
        "LOMI_E2_CONSUMER_DERIVATIVE_PRODUCT_RUNTIME": "true",
        "PGPORT": PORT,
        **s6_urls(socket_path),
    }
    validate_s6_private_environment(env, socket_path)
    return env


def s7_private_environment(work: Path, socket_path: str) -> dict[str, str]:
    env = s6_private_environment(work, socket_path)
    env.update({
        "LOMI_E2_CONSUMER_DERIVATIVE_POPULATED_RUNTIME": "true",
        "LOMI_E2_S7_SOURCE_ROOT": str(work / "s7-sources"),
        "LOMI_E2_S7_PLAN_PATH": str(work / "s7-plan.json"),
        "LOMI_E2_S7_OUTPUT_PATH": str(work / "s7-output.json"),
    })
    return env


def validate_private_server_settings(row: dict, work: Path) -> None:
    expected = {
        "listen": "",
        "socket": str(work / "socket"),
        "data": str(work / "data"),
        "max": "16",
        "port": PORT,
        "version": PINNED_POSTGRES_TEXT_VERSION,
        "version_num": PINNED_POSTGRES_SERVER_VERSION_NUM,
    }
    if type(row) is not dict or row != expected:
        raise Rejected("private PostgreSQL socket/version/connection settings mismatch")


class Fixture:
    def __init__(self, owned, lock, work: Path, run_dir: Path,
                 started: float, work_deadline: float, final_deadline: float,
                 bun: Path, pg: Path, tool_hashes: dict, run_id: str):
        self.owned = owned
        self.lock = lock
        self.work = work
        self.run_dir = run_dir
        self.started = started
        self.work_deadline = work_deadline
        self.final_deadline = final_deadline
        self.bun = bun
        self.pg = pg
        self.tool_hashes_before = tool_hashes
        self.run_id = run_id
        self.env = private_environment(work)
        self.runner = BoundedProcess(owned, env=self.env, work=work,
                                     started=started, work_deadline=work_deadline,
                                     final_deadline=final_deadline, run_dir=run_dir)
        self.start_attempted = False
        self.marker = None
        self.stage_status = {f"S{i}": "NOT_RUN" for i in range(8)}
        self.stage_evidence = {}
        self.inputs_before = {}
        self.captures = {}
        self.filled_operators = {}
        self.prisma_project_source_hashes = None
        self.prisma_project_ready = False
        self.cleanup_evidence = {"completed": False, "status": "NOT_RUN"}

    def remaining(self, cleanup=False):
        deadline = self.final_deadline if cleanup else self.work_deadline
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeadlineExpired("original fixture deadline expired")
        return remaining

    def exe(self, name: str) -> Path:
        if name not in {"initdb", "postgres", "pg_ctl", "psql"}:
            raise Rejected("unapproved PostgreSQL executable")
        path = self.pg / "bin" / name
        if file_digest(path) != self.lock["postgresFiles"]["bin/" + name]:
            raise Rejected("PostgreSQL executable hash drift")
        return path

    def command(self, label, argv, **kwargs):
        return self.runner.command(label, argv, **kwargs)

    def version_checks(self):
        expected = self.lock["postgresVersion"]
        if expected != "18.6":
            raise Rejected("pinned PostgreSQL tool version is not 18.6")
        versions = {}
        for name in ("initdb", "postgres", "pg_ctl", "psql"):
            result = self.command(name + "-version", [str(self.exe(name)), "--version"], timeout=10)
            line = result["stdout"].decode("utf-8", "strict").strip()
            if line != f"{name} (PostgreSQL) {PINNED_POSTGRES_TEXT_VERSION}":
                raise Rejected("actual PostgreSQL client version mismatch: " + name)
            versions[name] = line
        bun_version = self.command("bun-version", [str(self.bun), "--version"], timeout=10)
        value = bun_version["stdout"].decode("ascii", "strict").strip()
        if value != self.lock["bunVersion"]:
            raise Rejected("actual Bun version mismatch")
        versions["bun"] = value
        return versions

    def psql(self, database: str, *, user="e2_owner", script: bytes | None = None,
             source_path: Path | None = None, label="sql", output_file: Path | None = None,
             expected=(0,), max_output=PROCESS_OUTPUT_LIMIT, timeout=120,
             extra_args=(), catalog_search_path=False):
        if database not in DATABASES.values() and database != "postgres":
            raise Rejected("database name is outside the private fixture")
        if user not in {"e2_owner", "lomi_migrator", "lomi_runtime", "lomi_remote_api", "lomi_remote_exchange"}:
            raise Rejected("unapproved private database role")
        if script is not None and source_path is not None:
            raise Rejected("SQL must come from one exact source or one generated private copy")
        if script is not None:
            source_path = write_work_source(self.work, f"sql-{self.runner.serial + 1:03d}-{label}.sql", script)
        argv = [str(self.exe("psql")), "-X", "--no-psqlrc", "-w", "-v", "ON_ERROR_STOP=1",
                "-h", str(self.work / "socket"), "-p", PORT, "-U", user, "-d", database,
                "-qAt"]
        if source_path is not None:
            argv.extend(["-f", str(source_path)])
        argv.extend(extra_args)
        env = catalog_operator_environment(self.env) if catalog_search_path else None
        return self.command(label, argv, timeout=timeout, expected=expected,
                            output_limit=max_output, stdout_file=output_file, env=env)

    def apply_source(self, database: str, relative: str, *, migrator=False):
        source = safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT)
        if migrator:
            source = b"SET ROLE lomi_migrator;\n" + source
            db_tag = re.sub(r"[^a-z0-9-]+", "-", database.lower())[:32]
            private = write_work_source(self.work, f"migrator-{self.runner.serial + 1:03d}-{db_tag}-{Path(relative).name}", source)
            result = self.psql(database, source_path=private, label="apply-" + Path(relative).stem)
        else:
            result = self.psql(database, source_path=source_input(relative), label="apply-" + Path(relative).stem)
        return {"source": relative, "sourceSha256": digest(safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT)),
                "emittedSha256": digest(source), "command": result["label"]}

    def apply_script(self, database: str, raw: bytes, label: str, *, user="e2_owner"):
        path = write_work_source(self.work, f"{self.runner.serial + 1:03d}-{label}.sql", raw)
        return self.psql(database, user=user, source_path=path, label=label)

    def prepare_prisma_project(self) -> dict:
        project = self.work / PRISMA_PROJECT_CHILD
        if project.is_symlink() or not project.is_dir() or any(project.iterdir()):
            raise Rejected("private Prisma project directory must start empty")
        source_paths = prisma_migration_source_paths(self.lock["sourceAllowlist"])
        source_hashes = {}
        for relative in source_paths:
            raw = safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT)
            if digest(raw) != self.lock["sourceAllowlist"].get(relative):
                raise Rejected("Prisma project source hash differs from source lock")
            if relative == "auth-app/prisma.config.ts":
                validate_prisma_config_source(raw)
            local = relative.removeprefix("auth-app/")
            source_hashes[local] = digest(raw)
        self.prisma_project_source_hashes = source_hashes
        for relative in source_paths:
            raw = safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT)
            local = relative.removeprefix("auth-app/")
            target = project / local
            parent = project
            for part in Path(local).parts[:-1]:
                parent = parent / part
                if parent.exists() or parent.is_symlink():
                    if (parent.is_symlink() or not parent.is_dir()
                            or stat.S_IMODE(parent.stat().st_mode) != 0o700):
                        raise Rejected("private Prisma project parent directory identity drift")
                else:
                    os.mkdir(parent, 0o700)
            if target.exists() or target.is_symlink():
                raise Rejected("private Prisma project source path already exists")
            write_new(target, raw)
        dependency_target = self.lock.get("runtimeDependencyPath")
        if (dependency_target != str(WORKSPACE / "auth-app/node_modules")
                or Path(dependency_target).is_symlink() or not Path(dependency_target).is_dir()):
            raise Rejected("private Prisma project dependency target is not pinned")
        os.symlink(dependency_target, project / "node_modules")
        if os.readlink(project / "node_modules") != dependency_target:
            raise Rejected("private Prisma project dependency link target drift")
        validate_prisma_project_tree(project, source_hashes, dependency_target, require_complete=True)
        self.prisma_project_ready = True
        migrations = [name for name in source_paths if name.endswith("/migration.sql")]
        return {
            "directory": str(project),
            "sourceFiles": {name: source_hashes[name.removeprefix("auth-app/")]
                            for name in source_paths},
            "migrationCount": len(migrations),
            "dependencyLink": dependency_target,
            "cliSha256": self.lock["prismaCliSha256"],
            "schemaEngineSha256": self.lock["prismaSchemaEngineSha256"],
            "dotenvFilesCopied": False,
        }

    def run_prisma_migration_deploy(self, database: str, expected_rows: list[dict]) -> dict:
        if database not in DATABASES.values() or not self.prisma_project_ready:
            raise Rejected("Prisma migrate deploy requires the prepared private workspace")
        project = self.work / PRISMA_PROJECT_CHILD
        dependency_target = self.marker["prismaDependencyLink"]
        validate_prisma_project_tree(project, self.prisma_project_source_hashes,
                                     dependency_target, require_complete=True)
        cli_path = Path(self.lock["prismaCliPath"])
        engine_path = Path(self.lock["prismaSchemaEnginePath"])
        if (cli_path != PRISMA_CLI_PATH or engine_path != PRISMA_SCHEMA_ENGINE_PATH
                or file_digest(cli_path) != self.lock["prismaCliSha256"]
                or file_digest(engine_path) != self.lock["prismaSchemaEngineSha256"]):
            raise Rejected("Prisma CLI or schema-engine hash changed before migration deployment")
        socket_path = str(self.work / "socket")
        env = prisma_migration_environment(self.work, database, socket_path, engine_path)
        command = self.command(
            "prisma-migrate-deploy-" + database.replace("_", "-"),
            prisma_migration_argv(self.bun),
            timeout=PRISMA_MIGRATION_TIMEOUT,
            output_limit=PROCESS_OUTPUT_LIMIT,
            cwd=project,
            env=env,
        )
        if (file_digest(cli_path) != self.lock["prismaCliSha256"]
                or file_digest(engine_path) != self.lock["prismaSchemaEngineSha256"]):
            raise Rejected("Prisma CLI or schema-engine hash changed during migration deployment")
        validate_prisma_project_tree(project, self.prisma_project_source_hashes,
                                     dependency_target, require_complete=True)
        ledger_sql = b'''SELECT json_build_object(
 'migrationName', migration_name,
 'checksum', checksum,
 'finishedAt', finished_at,
 'rolledBackAt', rolled_back_at)::text
FROM public."_prisma_migrations"
ORDER BY migration_name;
'''
        ledger_raw = self.capture_query(
            database, ledger_sql, "prisma-ledger-" + database.replace("_", "-"))
        ledger_rows = validate_prisma_migration_ledger(ledger_raw, expected_rows)
        return {
            "database": database,
            "loginRole": "lomi_migrator",
            "port": PORT,
            "socketDirectory": socket_path,
            "migrationUrlSha256": digest(env["MIGRATION_DATABASE_URL"].encode("utf-8")),
            "pgPortMatchesUrl": True,
            "prismaVersion": self.lock["dependencyVersions"]["prisma"],
            "command": {
                "executable": str(self.bun),
                "executableSha256": self.lock["bunSha256"],
                "argv": prisma_migration_argv(self.bun)[1:],
                "cwd": str(project),
                "timeoutSeconds": PRISMA_MIGRATION_TIMEOUT,
                "environmentKeys": sorted(env),
                "returnCode": command["returnCode"],
                "stdoutBytes": command["stdoutBytes"],
                "stdoutSha256": command["stdoutSha256"],
                "stderrBytes": command["stderrBytes"],
                "stderrSha256": command["stderrSha256"],
            },
            "cliSha256": self.lock["prismaCliSha256"],
            "schemaEngineSha256": self.lock["prismaSchemaEngineSha256"],
            "ledgerCaptureSha256": digest(ledger_raw),
            "ledgerCaptureBytes": len(ledger_raw),
            "ledgerRows": ledger_rows,
            "allPinnedMigrationsFinishedWithExactChecksums": True,
            "productionLedgerQualification": "NOT_CLAIMED",
        }

    def create_cluster(self):
        private_dir(self.work, uid=os.getuid())
        self.marker = write_private_marker(self.work, run_id=self.run_id,
                                           bundle_manifest_sha=self.lock["bundleManifestSha256"])
        for name in ("home", "tmp", "socket", "data", "sql", "bun-project", PRISMA_PROJECT_CHILD):
            os.mkdir(self.work / name, 0o700)
        for name in ("pgpass-empty", "pg_service.conf.empty"):
            write_new(self.work / "home" / name, b"")
        versions = self.version_checks()
        init = self.command("initdb-private", [str(self.exe("initdb")), "-D", str(self.work / "data"),
                                               "-U", "e2_owner", "--auth=trust", "--no-locale", "-E", "UTF8"],
                            timeout=90)
        self.start_attempted = True
        options = ("-c listen_addresses= -k " + str(self.work / "socket") + " -p " + PORT
                   + " -c max_connections=16 -c superuser_reserved_connections=0"
                   + " -c reserved_connections=0 -c unix_socket_permissions=0700"
                   + " -c statement_timeout=55000 -c lock_timeout=10000"
                   + " -c idle_in_transaction_session_timeout=55000")
        start = self.command("pg-ctl-start", [str(self.exe("pg_ctl")), "-D", str(self.work / "data"),
                                               "-l", str(self.work / "postgres.log"), "-o", options,
                                               "-w", "-t", "30", "start"], timeout=45)
        settings_sql = b"""SELECT json_build_object(
 'listen',current_setting('listen_addresses'),
 'socket',current_setting('unix_socket_directories'),
 'data',current_setting('data_directory'),
 'max',current_setting('max_connections'),
 'port',current_setting('port'),
 'version',current_setting('server_version'),
 'version_num',current_setting('server_version_num'));
"""
        raw = self.capture_query("postgres", settings_sql, "server-settings")
        row = strict_json(raw.strip(), "private PostgreSQL settings")
        validate_private_server_settings(row, self.work)
        return {"actualVersions": versions, "initdb": init["returnCode"], "pgCtlStart": start["returnCode"],
                "settings": row, "socketOnly": True}

    def capture_query(self, database: str, sql: bytes, label: str) -> bytes:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", label):
            raise Rejected("unsafe capture label")
        capture = self.run_dir / (label + ".capture.jsonl")
        if capture.exists():
            raise Rejected("capture output already exists")
        self.psql(database, script=sql, label=label + "-query", output_file=capture,
                  max_output=CATALOG_OUTPUT_LIMIT)
        raw = safe_read(capture, max_bytes=CATALOG_OUTPUT_LIMIT)
        self.captures[label] = raw
        return raw

    def capture_catalog(self, database: str, label: str) -> bytes:
        sql = safe_read(HERE / CAPTURE_NAME, max_bytes=1024 * 1024)
        raw = self.capture_query(database, sql, label)
        _, evidence, _ = load_local_modules()
        evidence.verify_capture(raw)
        return raw

    def capture_functions(self, database: str, label: str) -> dict:
        _, evidence, _ = load_local_modules()
        raw = self.capture_catalog(database, label)
        return evidence.verify_capture(raw)["functions"]

    def cleanup(self):
        if self.marker is None:
            return {"completed": True, "serverStatus": "NOT_STARTED", "workRemoved": False}
        validate_work_marker(self.work, self.marker)
        status_before = None
        if self.start_attempted:
            status = self.command("pg-ctl-status-before-cleanup", [str(self.exe("pg_ctl")), "-D",
                                                                   str(self.work / "data"), "status"],
                                  timeout=8, expected=(0, 3), cleanup=True)
            status_before = status["returnCode"]
            pid_file = self.work / "data/postmaster.pid"
            if status_before == 0:
                if pid_file.is_symlink() or not pid_file.is_file():
                    raise Rejected("owned server status lacks its private postmaster identity")
                pid_lines = safe_read(pid_file, max_bytes=4096).decode("ascii", "strict").splitlines()
                if (len(pid_lines) < 6 or not pid_lines[0].isdigit()
                        or pid_lines[1] != str(self.work / "data")
                        or pid_lines[3] != PORT or pid_lines[4] != str(self.work / "socket")):
                    raise Rejected("owned postmaster identity differs from marker")
                self.command("pg-ctl-stop-owned", [str(self.exe("pg_ctl")), "-D",
                                                    str(self.work / "data"), "-m", "immediate",
                                                    "-w", "-t", "20", "stop"],
                             timeout=25, cleanup=True)
            status_after = self.command("pg-ctl-status3-after-cleanup", [str(self.exe("pg_ctl")), "-D",
                                                                         str(self.work / "data"), "status"],
                                        timeout=8, expected=(3,), cleanup=True)
            if (self.work / "data/postmaster.pid").exists():
                raise Rejected("postmaster pid file remains after pg_ctl status 3")
            socket_entries = list((self.work / "socket").iterdir())
            if socket_entries:
                raise Rejected("private PostgreSQL socket directory is not empty")
        else:
            status_after = {"returnCode": "NOT_STARTED"}
        prisma_project = self.work / PRISMA_PROJECT_CHILD
        if self.prisma_project_source_hashes is None:
            validate_prisma_project_tree(prisma_project, {}, self.marker["prismaDependencyLink"],
                                         require_complete=True)
        else:
            validate_prisma_project_tree(prisma_project, self.prisma_project_source_hashes,
                                         self.marker["prismaDependencyLink"],
                                         require_complete=self.prisma_project_ready)
        allowed = {"data", "socket", "home", "tmp", "sql", "bun-project", PRISMA_PROJECT_CHILD,
                   "fixture.marker.json", "postgres.log",
                   "s7-sources", "s7-plan.json", "s7-output.json"}
        actual = {entry.name for entry in self.work.iterdir()}
        if actual - allowed:
            raise Rejected("fixture work directory contains unmarked entries")
        if not {"data", "socket", "home", "tmp", "sql", "bun-project",
                PRISMA_PROJECT_CHILD, "fixture.marker.json"} <= actual:
            raise Rejected("fixture work directory is incomplete")
        approved_links = {
            "bun-project/node_modules": self.marker["runtimeDependencyLink"],
            PRISMA_PROJECT_CHILD + "/node_modules": self.marker["prismaDependencyLink"],
        }
        for path in self.work.rglob("*"):
            info = path.lstat()
            if info.st_uid != os.getuid():
                raise Rejected("fixture work contains an unowned entry")
            if path.is_symlink():
                relative = path.relative_to(self.work).as_posix()
                if relative not in approved_links or os.readlink(path) != approved_links[relative]:
                    raise Rejected("fixture work directory contains an unapproved symlink")
            elif not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
                raise Rejected("fixture work contains a special entry")
        # Recursive disposal is admitted only for this exact marked tree after
        # pg_ctl status 3, absent postmaster.pid, and an empty socket directory.
        if self.start_attempted and status_after["returnCode"] != 3:
            raise Rejected("owned PostgreSQL shutdown is not independently confirmed")
        shutil.rmtree(self.work)
        self.cleanup_evidence = {"completed": True, "pgCtlStatusBefore": status_before,
                                 "pgCtlStatusAfter": status_after["returnCode"],
                                 "postmasterPidAbsent": True, "socketDirectoryEmpty": True,
                                 "markedTreeRemoved": True}
        return self.cleanup_evidence


def import_owned_process() -> object:
    path = HERE / "inputs/lomi-remote/tools/owned_process.py"
    if path.is_symlink() or not path.is_file():
        raise Rejected("bundled owned-process helper unavailable")
    spec = importlib.util.spec_from_file_location("consumer_v3_owned_process", path)
    if spec is None or spec.loader is None:
        raise Rejected("owned-process helper load failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.initialize_process_ownership()
    module.require_process_ownership()
    return module


def run_workspace_preflight(lock: dict, manifest: dict) -> dict:
    _, _, prepare = load_local_modules()
    lock_loaded, _ = prepare.load_lock()
    current = prepare.verify_allowlist(WORKSPACE, lock_loaded)
    if current != {name: (HERE / "inputs" / name).read_bytes() for name in lock["sourceAllowlist"]}:
        raise Rejected("prepared inputs differ from current pinned source closure")
    if prepare.make_manifest(safe_read(HERE / "inputs.lock.json", max_bytes=2 * 1024 * 1024),
                             {**current, **{name: safe_read(HERE / name, max_bytes=8 * 1024 * 1024)
                                           for name in prepare.LOCAL_FILES}},
                             safe_read(HERE / "plan.json", max_bytes=64 * 1024)) != manifest:
        raise Rejected("prepared source manifest mismatch")
    package = checked_package_validator()
    tools = verify_toolchain(lock)
    return {"sourceClosure": {name: digest(raw) for name, raw in sorted(current.items())},
            "package": package, "toolchain": tools}


def create_database_roles(fixture: Fixture):
    fixture.apply_script("postgres", ROLE_SQL.encode("ascii"), "seed-synthetic-fixture-roles")
    for database in DATABASES.values():
        fixture.psql("postgres", script=(f"CREATE DATABASE {database} OWNER e2_owner TEMPLATE template0;\n".encode()),
                     label="create-" + database)
        fixture.psql(database, script=b"GRANT CREATE ON SCHEMA public TO lomi_migrator;\n",
                     label="migrator-public-create-" + database)
    return {"roleModel": "synthetic-private-fixture-only", "rolesCreated": [
        "e2_owner", "lomi_migrator", "lomi_runtime", "lomi_remote_api", "lomi_remote_exchange"],
        "migrationRoleLogin": True,
        "actualProductionRoleEvidence": False, "maxConnections": 16,
        "realRolePools": 4, "maximumConnectionsPerPool": 2}


def apply_active_baseline(fixture: Fixture):
    migrations = sorted(path for path in fixture.lock["sourceAllowlist"]
                        if path.startswith("auth-app/prisma/migrations/") and path.endswith("/migration.sql"))
    if not migrations or not any("202610220012" in path for path in migrations) or not any("202610220013" in path for path in migrations):
        raise Rejected("active migration closure must include 202610220012 and 202610220013")
    workspace = fixture.prepare_prisma_project()
    migration_inputs = {
        relative: safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT)
        for relative in migrations
    }
    expected_ledger = prisma_expected_migrations(migration_inputs)
    deployments = []
    operations_applied = []
    ops = (
        "auth-app/ops/database-permissions.sql",
        "auth-app/ops/remote-database-permissions.sql",
        "auth-app/ops/push-database-permissions.sql",
    )
    for database in DATABASES.values():
        deployments.append(fixture.run_prisma_migration_deploy(database, expected_ledger))
        for relative in ops:
            if relative not in fixture.lock["sourceAllowlist"]:
                raise Rejected("required active operations source is not pinned")
            operations_applied.append({"database": database, **fixture.apply_source(database, relative)})
    return {"migrationFiles": migrations, "migrationCountPerDatabase": len(migrations),
            "prismaWorkspace": workspace, "prismaDeployments": deployments,
            "prismaMigrationLedger": {
                "engine": "pinned Prisma " + fixture.lock["dependencyVersions"]["prisma"] + " migrate deploy",
                "expectedRows": expected_ledger,
                "allThreePrivateDatabaseLedgersVerified": True,
                "productionLedgerQualification": "NOT_CLAIMED",
                "productionMigrationHistoryUsed": False,
            },
            "operations": list(ops),
            "applications": len(deployments) + len(operations_applied),
            "emittedSources": operations_applied,
            "syntheticPrismaLedger": False,
            "prismaLedgerQualification": "PRIVATE_FIXTURE_ACTUAL_PRISMA_ENGINE_ONLY_NOT_PRODUCTION_QUALIFICATION"}


def successor_source_layers():
    return (
        PACKAGE_REL + "/inputs/frozen-v3-successor/approval-intent.candidate.sql",
        PACKAGE_REL + "/inputs/frozen-v3-successor/012-derivative-authority.candidate.sql",
        PACKAGE_REL + "/authority-core.candidate.sql",
        PACKAGE_REL + "/inputs/frozen-v3-successor/typed-entrypoints.candidate.sql",
    )


def execute_successor_source_layers(fixture: Fixture):
    records = []
    # reference-old remains the active-source contract for old-state pins.
    # The candidate layers are installed only in target and reference-new.
    for database in (DATABASES["target"], DATABASES["referenceNew"]):
        for relative in successor_source_layers():
            records.append({"database": database, **fixture.apply_source(database, relative, migrator=True)})
        records.append({"database": database,
                        **fixture.apply_source(database, PACKAGE_REL + "/typed-window-entrypoints.candidate.sql", migrator=True)})
        ownership = safe_read(PACKAGE / "fixture-ownership-bootstrap.sql", max_bytes=2 * 1024 * 1024)
        records.append({"database": database,
                        "command": fixture.apply_script(database, ownership, "fixture-ownership-bootstrap")["label"],
                        "sourceSha256": digest(ownership)})
    return {"sourceApplications": records,
            "ownershipBootstrapSha256": digest(safe_read(PACKAGE / "fixture-ownership-bootstrap.sql", max_bytes=2 * 1024 * 1024)),
            "sourceOnlyPrivateCopies": True}


def baseline_old_state(fixture: Fixture):
    raw = {}
    for database in (DATABASES["target"], DATABASES["referenceOld"], DATABASES["referenceNew"]):
        capture = fixture.capture_catalog(database, "baseline-" + database)
        raw[database] = capture
    _, evidence, _ = load_local_modules()
    if not evidence.stable_catalog_equality(raw[DATABASES["target"]], raw[DATABASES["referenceOld"]]):
        raise Rejected("active target does not equal independent reference-old baseline")
    if not evidence.stable_catalog_equality(raw[DATABASES["referenceOld"]], raw[DATABASES["referenceNew"]]):
        raise Rejected("independent databases do not share an identical active baseline")
    return raw


def operator_postcondition_statements(raw: bytes, *, marker: str, end_marker: str,
                                      expected: tuple[str, ...]) -> tuple[str, ...]:
    """Extract an exact literal statement block following a pinned operator guard."""
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise Rejected("operator source is not UTF-8") from error
    if text.count(marker) != 1:
        raise Rejected("operator postcondition marker multiplicity drift")
    start = text.index(marker) + len(marker)
    if text.count(end_marker) < 1:
        raise Rejected("operator postcondition end marker is missing")
    end = text.find(end_marker, start)
    if end < 0:
        raise Rejected("operator postcondition block is not closed")
    block = text[start:end]
    recognized = ("ALTER FUNCTION ", "REVOKE ALL ON FUNCTION ", "GRANT EXECUTE ON FUNCTION ")
    statements = []
    pending = ""
    for line in block.splitlines():
        stripped = line.strip()
        if not pending and not stripped.startswith(recognized):
            continue
        pending = (pending + " " + stripped).strip()
        if ";" in stripped:
            if stripped.count(";") != 1 or not stripped.endswith(";"):
                raise Rejected("operator ACL statement has an unexpected delimiter")
            statements.append(" ".join(pending.split()))
            pending = ""
    if pending or tuple(statements) != expected:
        raise Rejected("operator literal owner/ACL statement closure drift")
    return tuple(statements)


def helper_seal_reference_statements(raw: bytes, signatures: tuple[str, ...]) -> tuple[bytes, tuple[str, ...]]:
    expected_signatures = (
        "public.lomi_consumer_principal_live_v2(public.consumer_authorization)",
        "public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea)",
    )
    if signatures != expected_signatures:
        raise Rejected("helper seal reference signature closure drift")
    create_role = role_create_sql_from_operator(raw)
    expected_role = b"CREATE ROLE lomi_consumer_auth_body_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;"
    if create_role != expected_role:
        raise Rejected("body-owner role bootstrap literal drift")
    statements = operator_postcondition_statements(
        raw,
        marker=" IF seen_new=2 THEN RETURN; END IF;",
        end_marker=" FOR r IN SELECT value FROM jsonb_array_elements(pins) LOOP",
        expected=(
            "ALTER FUNCTION " + expected_signatures[0] + " OWNER TO lomi_consumer_auth_body_owner;",
            "ALTER FUNCTION " + expected_signatures[1] + " OWNER TO lomi_consumer_auth_body_owner;",
            "REVOKE ALL ON FUNCTION " + expected_signatures[0] + "," + expected_signatures[1]
            + " FROM PUBLIC,lomi_migrator,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_pairing_write_owner,lomi_remote_inventory_owner;",
            "GRANT EXECUTE ON FUNCTION " + expected_signatures[0]
            + " TO lomi_runtime,lomi_remote_inventory_owner;",
            "GRANT EXECUTE ON FUNCTION " + expected_signatures[1]
            + " TO lomi_remote_inventory_owner;",
        ),
    )
    return create_role, statements


def add_body_helper_reference_state(fixture: Fixture, helper_old_capture: bytes):
    """Construct the exact operator-sealed helper state and capture it separately."""
    helper_contract_raw = safe_read(PACKAGE / "helper-seal.pending.json", max_bytes=256 * 1024)
    helper_contract = strict_json(helper_contract_raw, "helper-seal pending contract")
    expected = (
        "public.lomi_consumer_principal_live_v2(public.consumer_authorization)",
        "public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea)",
    )
    rows = helper_contract.get("helpers")
    if type(rows) is not list or tuple(row.get("signature") for row in rows) != expected:
        raise Rejected("helper reference constructor signature closure drift")
    helper_operator = safe_read(PACKAGE / "operator-seal-auth-helpers.candidate.sql",
                                max_bytes=2 * 1024 * 1024)
    old_functions = function_map(load_local_modules()[1], helper_old_capture)
    if set(old_functions) < set(expected):
        raise Rejected("post-source helper reference capture is incomplete")
    for row in rows:
        old_row = old_functions[row["signature"]]
        if (old_row["owner"] != row["old_owner"] or old_row["securityDefiner"]
                or old_row["definitionUtf8Hex"] != old_row["definition"].encode("utf-8").hex()):
            raise Rejected("post-source helper row does not match the old helper contract")
    create_role, statements = helper_seal_reference_statements(helper_operator, expected)
    role_count = fixture.capture_query(
        "postgres", b"SELECT count(*) FROM pg_roles WHERE rolname='lomi_consumer_auth_body_owner';\n",
        "reference-new-body-owner-role-count",
    )
    if role_count.strip() == b"0":
        fixture.apply_script("postgres", create_role + b"\n",
                             "create-body-owner-once-for-reference-new")
    elif role_count.strip() != b"1":
        raise Rejected("body-owner cluster role count is ambiguous")
    role_state = fixture.capture_query(
        "postgres",
        b"SELECT json_build_object('login',rolcanlogin,'inherit',rolinherit,'super',rolsuper,'createdb',rolcreatedb,'createrole',rolcreaterole,'replication',rolreplication,'bypassRls',rolbypassrls,'config',rolconfig) FROM pg_roles WHERE rolname='lomi_consumer_auth_body_owner';\n",
        "reference-new-body-owner-role-state",
    )
    if strict_json(role_state.strip(), "body-owner role state") != {
        "login": False, "inherit": False, "super": False, "createdb": False,
        "createrole": False, "replication": False, "bypassRls": False, "config": None,
    }:
        raise Rejected("body owner role has unexpected global attributes")
    raw = ("BEGIN;\n" + "\n".join(statements) + "\nCOMMIT;\n").encode("utf-8")
    result = fixture.apply_script(DATABASES["referenceNew"], raw, "reference-new-helper-owner-state")
    capture = fixture.capture_catalog(DATABASES["referenceNew"], "s3-reference-new-post-helper-seal")
    new_functions = function_map(load_local_modules()[1], capture)
    for row in rows:
        new_row = new_functions[row["signature"]]
        if (new_row["owner"] != row["new_owner"] or new_row["securityDefiner"]
                or new_row["definitionUtf8Hex"] != old_functions[row["signature"]]["definitionUtf8Hex"]):
            raise Rejected("sealed helper reference differs from operator owner/ACL-only transition")
    return {"scriptSha256": digest(raw), "command": result["label"],
            "sourceContractSha256": digest(helper_contract_raw),
            "independentReference": DATABASES["referenceNew"],
            "literalOperatorRoleSqlSha256": digest(create_role),
            "literalOperatorAclStatementsSha256": digest("\n".join(statements).encode("utf-8"))}, capture


def literal_root_acl_statements(raw: bytes, signature: str) -> tuple[str, ...]:
    expected = (
        "REVOKE ALL ON FUNCTION " + signature
        + " FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner;",
        "GRANT EXECUTE ON FUNCTION " + signature + " TO lomi_remote_pairing_write_owner;",
    )
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise Rejected("three-root operator source is not UTF-8") from error
    revoke = re.findall(r"(?m)^\s*(REVOKE ALL ON FUNCTION public\.lomi_consumer_inventory\([^\n]+;)$", text)
    grant = re.findall(r"(?m)^\s*(GRANT EXECUTE ON FUNCTION public\.lomi_consumer_inventory\([^\n]+;)$", text)
    if tuple(" ".join(item.split()) for item in (*revoke, *grant)) != tuple(" ".join(item.split()) for item in expected):
        raise Rejected("three-root inventory ACL literal statement closure drift")
    if len(revoke) != 1 or len(grant) != 1:
        raise Rejected("three-root operator must contain exactly one inventory ACL delta")
    return tuple(" ".join(item.split()) for item in (revoke[0], grant[0]))


def apply_literal_root_state(fixture: Fixture):
    frozen = PACKAGE / "inputs/frozen-v3-successor"
    three_raw = safe_read(frozen / "operator-three-roots.candidate.sql", max_bytes=2 * 1024 * 1024)
    three_names = ("lomi_consumer_inventory", "lomi_consumer_assertion_recheck", "lomi_consumer_recipient_recheck")
    three_defs = literal_operator_definitions(three_raw, 3, three_names)
    inventory_signature = "public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)"
    acl_statements = literal_root_acl_statements(three_raw, inventory_signature)
    direct = (b"BEGIN;\n" + b"\n".join(three_defs)
              + b"\n" + "\n".join(acl_statements).encode("utf-8") + b"\nCOMMIT;\n")
    result = fixture.apply_script(DATABASES["referenceNew"], direct, "reference-new-literal-root-state")
    capture = fixture.capture_catalog(DATABASES["referenceNew"], "s3-reference-new-post-three-roots")
    return {"threeRootSourceSha256": digest(three_raw),
            "emittedDefinitionSha256": [digest(item) for item in three_defs],
            "inventoryAclStatementsSha256": digest("\n".join(acl_statements).encode("utf-8")),
            "directReferenceScriptSha256": digest(direct), "command": result["label"]}, capture


def apply_literal_channel_state(fixture: Fixture):
    source = PACKAGE / "operator-product-channels.candidate.sql"
    raw = safe_read(source, max_bytes=2 * 1024 * 1024)
    names = ("lomi_channel_consumer_prepare", "lomi_channel_peer_consumer_read",
             "lomi_channel_consumer_finalize", "lomi_ticket_consumer_prepare",
             "lomi_ticket_consumer_finalize")
    definitions = literal_operator_definitions(raw, 5, names)
    direct = b"BEGIN;\n" + b"\n".join(definitions) + b"\nCOMMIT;\n"
    result = fixture.apply_script(DATABASES["referenceNew"], direct,
                                  "reference-new-literal-channel-state")
    capture = fixture.capture_catalog(DATABASES["referenceNew"], "s3-reference-new-post-channel")
    return {"channelSourceSha256": digest(raw),
            "emittedDefinitionSha256": [digest(item) for item in definitions],
            "directReferenceScriptSha256": digest(direct), "command": result["label"]}, capture


PHASE_CAPTURE_KEYS = frozenset((
    "activeBaseline", "postSourcePreSeal", "postHelperSeal", "postThreeRoots",
    "preChannelAccess", "postChannel",
))


def derive_phase_pin_values(contract: dict, helper_contract: dict, channel: dict,
                            phase_captures: dict[str, bytes]):
    _, evidence, _ = load_local_modules()
    if type(phase_captures) is not dict or set(phase_captures) != PHASE_CAPTURE_KEYS:
        raise Rejected("independent reference phase capture closure is incomplete")
    for name, raw in phase_captures.items():
        if type(raw) is not bytes:
            raise Rejected("reference phase capture is not raw bytes: " + name)
        evidence.verify_capture(raw)
    primary_values, primary_correlations = evidence.pin_values_from_references(
        contract,
        phase_captures["activeBaseline"],
        phase_captures["postThreeRoots"],
        helper_contract,
        phase_captures["postSourcePreSeal"],
        phase_captures["postHelperSeal"],
    )
    channel_values, channel_correlations = evidence.pin_values_from_references(
        channel,
        phase_captures["preChannelAccess"],
        phase_captures["postChannel"],
        {"status": channel.get("status"), "helpers": []},
        phase_captures["preChannelAccess"],
        phase_captures["postChannel"],
    )
    return primary_values, primary_correlations, channel_values, channel_correlations


def phase_pin_capture_mapping() -> dict[str, dict[str, str]]:
    """Document the exact independent state used for every pin family."""
    return {
        "threeRootOld": {"contract": "activeBaseline"},
        "threeRootNewAndPrerequisites": {"contract": "postThreeRoots"},
        "helperOld": {"contract": "postSourcePreSeal"},
        "helperNew": {"contract": "postHelperSeal"},
        "channelOld": {"contract": "preChannelAccess"},
        "channelNewAndPrerequisites": {"contract": "postChannel"},
    }


def build_pin_copies(fixture: Fixture, phase_captures: dict[str, bytes]):
    _, evidence, _ = load_local_modules()
    frozen = PACKAGE / "inputs/frozen-v3-successor"
    contract_raw = safe_read(frozen / "catalog-contract.pending.json", max_bytes=512 * 1024)
    helper_raw = safe_read(PACKAGE / "helper-seal.pending.json", max_bytes=256 * 1024)
    channel_raw = safe_read(PACKAGE / "channel-transition.pending.json", max_bytes=512 * 1024)
    contract = strict_json(contract_raw, "catalog contract")
    helper_contract = strict_json(helper_raw, "helper contract")
    channel = strict_json(channel_raw, "channel contract")
    evidence.validate_null_pins(contract, helper_contract)
    evidence.validate_null_pins(channel, {"status": channel.get("status"), "helpers": []})
    primary_values, primary_correlations, channel_values, channel_correlations = derive_phase_pin_values(
        contract, helper_contract, channel, phase_captures)
    channel_pins = channel_values["catalog-contract.pending.json"]
    if any(channel_pins[("roots", index, "old_acl")]
           != channel_pins[("roots", index, "new_acl")]
           for index in range(len(channel["roots"]))):
        raise Rejected("product-channel operator requires unchanged root ACLs")
    filled_contract, contract_deltas = evidence.fill_null_spans(
        contract_raw, primary_values["catalog-contract.pending.json"],
        primary_correlations["catalog-contract.pending.json"])
    filled_helper, helper_deltas = evidence.fill_null_spans(
        helper_raw, primary_values["helper-seal.pending.json"],
        primary_correlations["helper-seal.pending.json"])
    filled_channel, channel_deltas = evidence.fill_null_spans(
        channel_raw, channel_values["catalog-contract.pending.json"],
        channel_correlations["catalog-contract.pending.json"])
    outputs = {
        "catalog-contract.measured.private.json": filled_contract,
        "helper-seal.measured.private.json": filled_helper,
        "channel-transition.measured.private.json": filled_channel,
    }
    for name, raw in outputs.items():
        write_new(fixture.work / "sql" / name, raw)
        write_new(fixture.run_dir / name, raw)

    def fill_operator(source: Path, work_name: str, evidence_name: str,
                      blocks: list[tuple[str, str, dict, dict, dict]]):
        original = safe_read(source, max_bytes=2 * 1024 * 1024)
        raw = original
        block_results = {}
        for marker, source_group, contract_obj, values, correlations in blocks:
            tag = marker.encode("ascii")
            if raw.count(tag) != 2:
                raise Rejected("operator contract marker multiplicity drift")
            text = raw.decode("utf-8", "strict")
            start = text.index(marker) + len(marker)
            end = text.index(marker, start)
            embedded = text[start:end].encode("utf-8")
            if strict_json(embedded, "operator embedded contract") != contract_obj[source_group]:
                raise Rejected("operator embedded contract differs from pinned pending source")
            raw, deltas = evidence.fill_operator_embedded_contract(
                raw, marker, embedded, source_group, values, correlations)
            block_results[marker] = {"pinDeltas": deltas}
        write_new(fixture.work / "sql" / work_name, raw)
        write_new(fixture.run_dir / evidence_name, raw)
        return {"sourceSha256": digest(original), "filledSha256": digest(raw),
                "blocks": block_results}

    helper_operator = PACKAGE / "operator-seal-auth-helpers.candidate.sql"
    three_operator = frozen / "operator-three-roots.candidate.sql"
    channel_operator = PACKAGE / "operator-product-channels.candidate.sql"
    filled = {
        "helperSeal": fill_operator(
            helper_operator, "operator-helper-seal.private.sql", "operator-helper-seal.private.sql",
            [("$helper_pins$", "helpers", helper_contract,
              primary_values["helper-seal.pending.json"],
              primary_correlations["helper-seal.pending.json"])],
        ),
        "threeRoots": fill_operator(
            three_operator, "operator-three-roots.private.sql", "operator-three-roots.private.sql",
            [("$pins$", "roots", contract,
              primary_values["catalog-contract.pending.json"],
              primary_correlations["catalog-contract.pending.json"]),
             ("$deps$", "prerequisites", contract,
              primary_values["catalog-contract.pending.json"],
              primary_correlations["catalog-contract.pending.json"])],
        ),
        "channelRoots": fill_operator(
            channel_operator, "operator-product-channels.private.sql", "operator-product-channels.private.sql",
            [("$roots$", "roots", channel,
              channel_values["catalog-contract.pending.json"],
              channel_correlations["catalog-contract.pending.json"]),
             ("$deps$", "prerequisites", channel,
              channel_values["catalog-contract.pending.json"],
              channel_correlations["catalog-contract.pending.json"])],
        ),
    }
    fixture.filled_operators = filled
    return {"sourceContractSha256": {"catalog": digest(contract_raw), "helpers": digest(helper_raw),
                                      "channel": digest(channel_raw)},
            "referenceCaptureSha256": {name: digest(raw) for name, raw in sorted(phase_captures.items())},
            "pinCapturePhaseByContract": phase_pin_capture_mapping(),
            "pinCounts": {"catalog": len(primary_values["catalog-contract.pending.json"]),
                          "helpers": len(primary_values["helper-seal.pending.json"]),
                          "channel": len(channel_values["catalog-contract.pending.json"])},
            "privateFillOutputs": filled,
            "targetDidNotSupplyPins": True}


def function_map(evidence, raw_capture: bytes) -> dict:
    return evidence.verify_capture(raw_capture)["functions"]


def assert_function_rows(fixture: Fixture, expected_capture: bytes, signatures: tuple[str, ...], label: str):
    _, evidence, _ = load_local_modules()
    expected = function_map(evidence, expected_capture)
    actual_capture = fixture.capture_catalog(DATABASES["target"], label)
    actual = function_map(evidence, actual_capture)
    if any(actual.get(signature) != expected.get(signature) for signature in signatures):
        raise Rejected("operator test did not restore the exact old function rows: " + label)
    return actual_capture


def assert_capture_function_rows(actual_capture: bytes, expected_functions: dict,
                                 signatures: tuple[str, ...], label: str) -> None:
    _, evidence, _ = load_local_modules()
    actual = function_map(evidence, actual_capture)
    if any(actual.get(signature) != expected_functions.get(signature)
           for signature in signatures):
        raise Rejected("captured function rows differ from independent phase state: " + label)


def restore_function_capture_row_sql(signature: str, desired_row: dict,
                                     current_row: dict) -> bytes:
    """Restore raw definition, owner, and expanded ACL from a capture row."""
    definition = desired_row.get("definition")
    current_definition = current_row.get("definition")
    if (type(definition) is not str or type(current_definition) is not str
            or "\x00" in definition or not definition
            or desired_row.get("definitionUtf8Hex") != definition.encode("utf-8").hex()
            or current_row.get("definitionUtf8Hex") != current_definition.encode("utf-8").hex()
            or desired_row.get("catalogSha256") != digest(definition.encode("utf-8"))
            or current_row.get("catalogSha256") != digest(current_definition.encode("utf-8"))):
        raise Rejected("captured function definition bytes are inconsistent")
    definition_bytes = definition.encode("utf-8")
    if not definition_bytes.endswith(b";") and not re.search(
            rb"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$\n?$", definition_bytes):
        raise Rejected("captured function definition has no safe SQL replay terminator")
    extra = set()
    for row in current_row.get("acl", []):
        if type(row) is not dict or type(row.get("grantee")) is not str:
            raise Rejected("current expanded ACL is malformed")
        if row["grantee"] != "PUBLIC":
            extra.add(row["grantee"])
    reset = restore_function_owner_acl_sql(signature, desired_row,
                                           extra_grantees=tuple(sorted(extra)))
    reset_lines = reset.splitlines()
    if len(reset_lines) < 3 or reset_lines[0] != b"BEGIN;" or reset_lines[-1] != b"COMMIT;":
        raise Rejected("function owner/ACL restoration wrapper drift")
    parts = [b"BEGIN;"]
    if definition != current_definition:
        # Keep the capture field and its hash byte-exact; add the SQL command
        # delimiter only to the private replay statement.
        replay_definition = definition_bytes
        replay_definition += b"\n" if definition_bytes.endswith(b";") else b";\n"
        parts.append(replay_definition)
    parts.extend(reset_lines[1:-1])
    parts.append(b"COMMIT;")
    return b"\n".join(parts) + b"\n"


def expected_operator_denial(fixture: Fixture, *, operator: Path, label: str,
                              expected_error: str, database=None, exact_reason=False):
    result = fixture.psql(database or DATABASES["target"], source_path=operator,
                          label=label, expected=(3,), timeout=30,
                          catalog_search_path=True,
                          extra_args=("-v", "VERBOSITY=verbose") if exact_reason else ())
    error_text = (result["stderr"] + b"\n" + result["stdout"]).decode("utf-8", "replace")
    if exact_reason:
        errors = re.findall(r"(?m)^[^\r\n]*\bERROR:\s+([0-9A-Z]{5}): ([^\r\n]+)\r?$", error_text)
        accepted = errors == [("P0001", expected_error)]
    else:
        accepted = expected_error in error_text
    if not accepted:
        raise Rejected("operator denial did not produce the expected fail-closed reason: " + label)
    return {"label": label, "returnCode": result["returnCode"],
            "expectedError": expected_error, "exactP0001ReasonVerified": exact_reason,
            "stderrSha256": result["stderrSha256"]}


def bypass_void_body_sql(row: dict) -> bytes:
    """Build only the private negative probe, preserving the captured header."""
    definition = row.get("definition")
    if (type(definition) is not str or row.get("definitionUtf8Hex") != definition.encode().hex()
            or row.get("catalogSha256") != digest(definition.encode())
            or definition.count("$function$") != 2):
        raise Rejected("body-drift probe requires exact deparsed function bytes")
    start = definition.index("$function$") + len("$function$")
    end = definition.index("$function$", start)
    header = definition[:start]
    if (not header.startswith("CREATE OR REPLACE FUNCTION public.lomi_")
            or "\n RETURNS void\n LANGUAGE plpgsql\n" not in header
            or definition[end + len("$function$"):] != "\n"):
        raise Rejected("body-drift probe requires the exact PG18 void/PLpgSQL shape")
    modified = header + "\nBEGIN RETURN; END;\n" + definition[end:]
    if modified == definition:
        raise Rejected("body-drift probe did not modify its target")
    return modified.encode("utf-8") + b";\n"


def run_catalog_body_denial(fixture: Fixture, *, operator: Path, signature: str,
                             expected_row: dict, label: str, expected_error: str):
    _, evidence, _ = load_local_modules()
    before = fixture.capture_catalog(DATABASES["target"], label + "-before")
    original = function_map(evidence, before).get(signature)
    if original != expected_row:
        raise Rejected("body-drift target differs from its independent phase row")
    sql = bypass_void_body_sql(original)
    fixture.apply_script(DATABASES["target"], sql, label + "-install-bypass")
    drift = fixture.capture_catalog(DATABASES["target"], label + "-modified")
    changed = function_map(evidence, drift)[signature]
    excluded = {"definition", "definitionUtf8Hex", "catalogSha256"}
    if (changed["definitionUtf8Hex"] == original["definitionUtf8Hex"]
            or {k: v for k, v in changed.items() if k not in excluded}
            != {k: v for k, v in original.items() if k not in excluded}):
        raise Rejected("catalog-body probe changed owner/ACL/security/config or left body unchanged")
    denial = expected_operator_denial(
        fixture, operator=operator, label=label + "-reject",
        expected_error=expected_error, exact_reason=True)
    after_denial = fixture.capture_catalog(DATABASES["target"], label + "-after-reject")
    if not evidence.exact_capture_equality(drift, after_denial):
        raise Rejected("body-drift operator denial changed catalog state")
    fixture.apply_script(
        DATABASES["target"], restore_function_capture_row_sql(signature, original, changed),
        label + "-restore")
    restored = fixture.capture_catalog(DATABASES["target"], label + "-restored")
    if not evidence.exact_capture_equality(before, restored):
        raise Rejected("body-drift probe did not restore the complete catalog")
    return {"signature": signature, "denial": denial, "bypassSqlSha256": digest(sql),
            "beforeCaptureSha256": digest(before), "modifiedCaptureSha256": digest(drift),
            "afterDenialCaptureSha256": digest(after_denial), "restoredCaptureSha256": digest(restored),
            "onlyBodyChanged": True, "denialPreservedModifiedState": True,
            "completeCatalogRestoredBeforePositiveControl": True}


def role_create_sql_from_operator(raw: bytes) -> bytes:
    text = raw.decode("utf-8", "strict")
    matches = re.findall(r"^\s*(CREATE ROLE lomi_consumer_auth_body_owner [^;]+;)$", text, re.M)
    if len(matches) != 1:
        raise Rejected("body-owner role bootstrap literal drift")
    return matches[0].strip().encode("utf-8")


def restore_function_owner_acl_sql(signature: str, old_row: dict,
                                   *, extra_grantees: tuple[str, ...] = ()) -> bytes:
    """Restore owner and expanded function ACL from an independent raw row."""
    owner = old_row.get("owner")
    acl = old_row.get("acl")
    if (not re.fullmatch(r"public\.lomi_[a-z0-9_]+\([A-Za-z0-9_.,()]+\)", signature)
            or type(owner) is not str or not re.fullmatch(r"[a-z_][a-z0-9_]*", owner)
            or type(acl) is not list):
        raise Rejected("old function owner/ACL restoration source is malformed")
    if type(extra_grantees) is not tuple:
        raise Rejected("ACL reset grantees must be a closed tuple")
    # ALTER OWNER can rewrite the previous owner's ACL entry to the new owner.
    # Reset that entry even when the desired capture deliberately omits it.
    grantees = {owner, *extra_grantees}
    grants = []
    seen_grants = set()
    for row in acl:
        if (type(row) is not dict
                or set(row) != {"grantor", "grantee", "privilege", "grantable"}
                or row.get("grantor") != owner
                or row.get("privilege") != "EXECUTE"
                or type(row.get("grantable")) is not bool):
            raise Rejected("expanded old ACL cannot be reconstructed without grantor drift")
        grantee = row.get("grantee")
        if grantee != "PUBLIC" and (type(grantee) is not str
                                     or not re.fullmatch(r"[a-z_][a-z0-9_]*", grantee)):
            raise Rejected("expanded old ACL has an unsafe grantee")
        key = (grantee, row["privilege"])
        if key in seen_grants:
            raise Rejected("expanded old ACL contains duplicate privilege rows")
        seen_grants.add(key)
        grantees.add(grantee)
        grants.append((grantee, row["grantable"]))
    for grantee in grantees:
        if grantee != "PUBLIC" and not re.fullmatch(r"[a-z_][a-z0-9_]*", grantee):
            raise Rejected("ACL reset grantee is unsafe")
    parts = ["BEGIN;", "ALTER FUNCTION " + signature + " OWNER TO " + owner + ";"]
    revoke = ["PUBLIC"] + sorted(grantee for grantee in grantees if grantee != "PUBLIC")
    parts.append("REVOKE ALL ON FUNCTION " + signature + " FROM " + ",".join(revoke) + ";")
    parts.append("SET ROLE " + owner + ";")
    for grantee, grantable in grants:
        target = "PUBLIC" if grantee == "PUBLIC" else grantee
        suffix = " WITH GRANT OPTION" if grantable else ""
        parts.append("GRANT EXECUTE ON FUNCTION " + signature + " TO " + target + suffix + ";")
    parts.extend(("RESET ROLE;", "COMMIT;"))
    return ("\n".join(parts) + "\n").encode("ascii")


def acl_drift_grantee(row: dict) -> str:
    acl = row.get("acl")
    if type(acl) is not list:
        raise Rejected("ACL drift probe requires an expanded function ACL")
    present = {item.get("grantee") for item in acl if type(item) is dict}
    for candidate in ("lomi_consumer_auth_body_owner", "lomi_remote_api",
                      "lomi_remote_exchange", "lomi_runtime",
                      "lomi_remote_inventory_owner"):
        if candidate not in present and candidate != row.get("owner"):
            return candidate
    raise Rejected("no measured absent grantee can produce a distinct ACL drift")


def run_operator_transitions(fixture: Fixture, old_capture: bytes,
                             post_source_capture: bytes, post_helper_capture: bytes,
                             post_three_roots_capture: bytes,
                             pre_channel_access_capture: bytes):
    """Exercise literal operator transitions against their independent phases."""
    _, evidence, _ = load_local_modules()
    frozen = PACKAGE / "inputs/frozen-v3-successor"
    helper_source = PACKAGE / "operator-seal-auth-helpers.candidate.sql"
    roots_source = frozen / "operator-three-roots.candidate.sql"
    channel_source = PACKAGE / "operator-product-channels.candidate.sql"
    helper_operator = fixture.work / "sql/operator-helper-seal.private.sql"
    roots_operator = fixture.work / "sql/operator-three-roots.private.sql"
    channel_operator = fixture.work / "sql/operator-product-channels.private.sql"
    for path in (helper_operator, roots_operator, channel_operator):
        if path.is_symlink() or not path.is_file():
            raise Rejected("measured private operator copy missing")
    old_functions = function_map(evidence, old_capture)
    post_source_functions = function_map(evidence, post_source_capture)
    post_helper_functions = function_map(evidence, post_helper_capture)
    post_three_root_functions = function_map(evidence, post_three_roots_capture)
    pre_channel_functions = function_map(evidence, pre_channel_access_capture)
    helper_rows = strict_json(safe_read(PACKAGE / "helper-seal.pending.json", max_bytes=256 * 1024), "helper contract")["helpers"]
    helper_sigs = tuple(row["signature"] for row in helper_rows)
    root_contract = strict_json(safe_read(frozen / "catalog-contract.pending.json", max_bytes=512 * 1024), "root contract")
    three_root_sigs = tuple(row["signature"] for row in root_contract["roots"])
    channel_contract = strict_json(safe_read(PACKAGE / "channel-transition.pending.json", max_bytes=512 * 1024), "channel contract")
    channel_sigs = tuple(row["signature"] for row in channel_contract["roots"])

    # Create one complete helper new-state row while its peer remains at the
    # independent post-source old state. The seal operator itself owns the
    # exact transition block and the references supply both complete rows.
    body_role_count = fixture.capture_query(
        "postgres", b"SELECT count(*) FROM pg_roles WHERE rolname='lomi_consumer_auth_body_owner';\n",
        "operator-body-owner-role-count",
    )
    if body_role_count.strip() != b"1":
        raise Rejected("helper operator role must already exist from reference setup")
    if any(signature not in post_source_functions or signature not in post_helper_functions
           for signature in helper_sigs):
        raise Rejected("helper mixed-state reference rows are incomplete")
    for signature in helper_sigs:
        old_row = post_source_functions[signature]
        new_row = post_helper_functions[signature]
        if old_row["definitionUtf8Hex"] != new_row["definitionUtf8Hex"]:
            raise Rejected("helper seal reference unexpectedly changes function definition")
    helper_first = helper_sigs[0]
    helper_current_capture = fixture.capture_catalog(DATABASES["target"], "s4-target-before-helper-mixed")
    helper_current = function_map(evidence, helper_current_capture)
    assert_capture_function_rows(helper_current_capture, post_source_functions, helper_sigs,
                                 "target-helper-old-state-matches-post-source-reference")
    fixture.apply_script(
        DATABASES["target"],
        restore_function_owner_acl_sql(
            helper_first, post_helper_functions[helper_first],
            extra_grantees=tuple(
                row["grantee"] for row in helper_current[helper_first]["acl"]
                if row["grantee"] != "PUBLIC"),
        ),
        "make-one-helper-complete-new-state",
    )
    helper_mixed_capture = fixture.capture_catalog(DATABASES["target"], "s4-target-helper-mixed-state")
    helper_expected_mixed = dict(post_source_functions)
    helper_expected_mixed[helper_first] = post_helper_functions[helper_first]
    assert_capture_function_rows(helper_mixed_capture, helper_expected_mixed, helper_sigs,
                                 "one-complete-new-helper-and-one-old-helper")
    helper_mixed_denial = expected_operator_denial(
        fixture, operator=helper_operator, label="helper-seal-mixed-denial",
        expected_error="mixed helper seal state")
    helper_current_capture = fixture.capture_catalog(DATABASES["target"], "s4-target-helper-mixed-before-restore")
    helper_current = function_map(evidence, helper_current_capture)
    fixture.apply_script(
        DATABASES["target"],
        restore_function_capture_row_sql(helper_first, post_source_functions[helper_first],
                                         helper_current[helper_first]),
        "restore-complete-old-helper-row-after-mixed",
    )
    assert_function_rows(fixture, post_source_capture, helper_sigs, "restore-helper-mixed-state")

    helper_drift_grantee = acl_drift_grantee(post_source_functions[helper_first])
    fixture.apply_script(DATABASES["target"],
                         ("GRANT EXECUTE ON FUNCTION " + helper_first + " TO "
                          + helper_drift_grantee + ";\n").encode(),
                         "make-helper-acl-drift")
    helper_drift_denial = expected_operator_denial(
        fixture, operator=helper_operator, label="helper-seal-acl-drift-denial",
        expected_error="unexpected helper definition/owner/ACL")
    fixture.apply_script(DATABASES["target"],
                         ("REVOKE EXECUTE ON FUNCTION " + helper_first + " FROM "
                          + helper_drift_grantee + ";\n").encode(),
                         "restore-helper-acl-after-drift")
    assert_function_rows(fixture, post_source_capture, helper_sigs, "restore-helper-acl-drift")
    helper_body_denial = run_catalog_body_denial(
        fixture, operator=helper_operator, signature=helper_sigs[0],
        expected_row=post_source_functions[helper_sigs[0]], label="helper-body-drift",
        expected_error="unexpected helper definition/owner/ACL: " + helper_sigs[0])

    helper_first = fixture.psql(DATABASES["target"], source_path=helper_operator,
                                label="helper-seal-all-old-transition",
                                catalog_search_path=True)
    helper_second = fixture.psql(DATABASES["target"], source_path=helper_operator,
                                 label="helper-seal-all-new-idempotency",
                                 catalog_search_path=True)
    if helper_first["returnCode"] != 0 or helper_second["returnCode"] != 0:
        raise Rejected("helper seal did not accept all-old then all-new state")
    helper_controls = {"helperSeal": {"allOldTransition": helper_first["returnCode"],
                                      "allNewIdempotent": helper_second["returnCode"]}}
    helper_owner_receipt, helper_owner_outcomes = run_owner_state_denials(
        fixture, {"operators": helper_controls}, operator_ids=("helperSeal",))

    # The three-root operator's old pins come from active baseline. Restore
    # those complete rows before its all-old transition, then exercise one
    # new function row whose ACL and owner are unchanged across the phases.
    if any(signature not in old_functions or signature not in post_three_root_functions
           for signature in three_root_sigs):
        raise Rejected("three-root phase reference rows are incomplete")
    current_target_capture = fixture.capture_catalog(DATABASES["target"], "s4-target-before-three-root-reset")
    current_target = function_map(evidence, current_target_capture)
    for signature in three_root_sigs:
        fixture.apply_script(
            DATABASES["target"],
            restore_function_capture_row_sql(signature, old_functions[signature],
                                             current_target[signature]),
            "restore-three-root-old-row-" + re.sub(r"[^a-z0-9]+", "-", signature.lower())[:36],
        )
    assert_function_rows(fixture, old_capture, three_root_sigs,
                         "prepare-three-roots-from-active-baseline")
    before_root_operator = fixture.capture_catalog(DATABASES["target"], "s4-target-before-three-root-operator")
    root_prerequisite_sigs = tuple(item["signature"] for item in root_contract["prerequisites"])
    assert_capture_function_rows(before_root_operator, post_three_root_functions,
                                 root_prerequisite_sigs,
                                 "three-root-prerequisites-match-post-three-roots-reference")
    assert_capture_function_rows(before_root_operator, post_helper_functions, helper_sigs,
                                 "sealed-helper-state-matches-independent-reference")
    mixed_root = next((signature for signature in three_root_sigs[1:]
                       if (old_functions[signature]["owner"] == post_three_root_functions[signature]["owner"]
                           and old_functions[signature]["acl"] == post_three_root_functions[signature]["acl"]
                           and old_functions[signature]["definitionUtf8Hex"]
                           != post_three_root_functions[signature]["definitionUtf8Hex"])), None)
    if mixed_root is None:
        raise Rejected("no non-inventory three-root row has an unchanged owner and ACL")
    fixture.apply_script(
        DATABASES["target"],
        restore_function_capture_row_sql(mixed_root, post_three_root_functions[mixed_root],
                                         old_functions[mixed_root]),
        "make-three-roots-mixed-with-complete-new-row",
    )
    mixed_capture = fixture.capture_catalog(DATABASES["target"], "s4-target-three-roots-mixed-state")
    mixed_expected = dict(old_functions)
    mixed_expected[mixed_root] = post_three_root_functions[mixed_root]
    assert_capture_function_rows(mixed_capture, mixed_expected, three_root_sigs,
                                 "one-complete-new-three-root-and-two-old-roots")
    roots_mixed_denial = expected_operator_denial(
        fixture, operator=roots_operator, label="three-roots-mixed-denial",
        expected_error="mixed catalog state rejected")
    mixed_capture = fixture.capture_catalog(DATABASES["target"], "s4-target-three-roots-mixed-before-restore")
    mixed_actual = function_map(evidence, mixed_capture)
    fixture.apply_script(DATABASES["target"],
                         restore_function_capture_row_sql(mixed_root, old_functions[mixed_root],
                                                          mixed_actual[mixed_root]),
                         "restore-complete-old-three-root-row-after-mixed")
    assert_function_rows(fixture, old_capture, three_root_sigs, "restore-three-roots-mixed")

    first_root = three_root_sigs[0]
    root_drift_grantee = acl_drift_grantee(old_functions[first_root])
    fixture.apply_script(DATABASES["target"],
                         ("GRANT EXECUTE ON FUNCTION " + first_root + " TO "
                          + root_drift_grantee + ";\n").encode(),
                         "make-three-root-acl-drift")
    roots_drift_denial = expected_operator_denial(
        fixture, operator=roots_operator, label="three-roots-acl-drift-denial",
        expected_error="unexpected root definition/ACL")
    fixture.apply_script(DATABASES["target"],
                         ("REVOKE EXECUTE ON FUNCTION " + first_root + " FROM "
                          + root_drift_grantee + ";\n").encode(),
                         "restore-three-root-acl-after-drift")
    assert_function_rows(fixture, old_capture, three_root_sigs, "restore-three-roots-acl-drift")
    roots_body_denial = run_catalog_body_denial(
        fixture, operator=roots_operator, signature=three_root_sigs[1],
        expected_row=old_functions[three_root_sigs[1]], label="three-root-body-drift",
        expected_error="unexpected root definition/ACL: " + three_root_sigs[1])
    roots_first = fixture.psql(DATABASES["target"], source_path=roots_operator,
                               label="three-roots-all-old-transition",
                               catalog_search_path=True)
    roots_second = fixture.psql(DATABASES["target"], source_path=roots_operator,
                                label="three-roots-all-new-idempotency",
                                catalog_search_path=True)
    if roots_first["returnCode"] != 0 or roots_second["returnCode"] != 0:
        raise Rejected("three-root operator did not accept all-old then all-new state")
    root_controls = {"threeRoots": {"allOldTransition": roots_first["returnCode"],
                                    "allNewIdempotent": roots_second["returnCode"]}}
    root_owner_receipt, root_owner_outcomes = run_owner_state_denials(
        fixture, {"operators": root_controls}, operator_ids=("threeRoots",))
    owner_module, owner_parameters = owner_state_parameters(
        fixture, {"operators": {**helper_controls, **root_controls}})
    owner_matrix = owner_module.validate_complete_matrix(
        fixture.run_id, helper_owner_outcomes + root_owner_outcomes, **owner_parameters)
    owner_matrix["measuredPhaseReceipts"] = {
        "postHelperSeal": helper_owner_receipt, "postThreeRoots": root_owner_receipt,
    }

    assert_function_rows(fixture, post_three_roots_capture, three_root_sigs,
                         "three-root-transition-matches-post-three-roots-reference")

    # Product grants are applied only after the three-root operator. They put
    # the target in the independently captured pre-channel state.
    access = safe_read(PACKAGE / "fixture-product-access.sql", max_bytes=2 * 1024 * 1024)
    target_access = fixture.apply_script(DATABASES["target"], access, "fixture-product-access-target")
    after_access_capture = fixture.capture_catalog(DATABASES["target"], "s4-target-after-product-access")
    pre_channel_functions = function_map(evidence, pre_channel_access_capture)
    assert_capture_function_rows(after_access_capture, pre_channel_functions,
                                 three_root_sigs + helper_sigs + channel_sigs,
                                 "product-access-matches-complete-pre-channel-reference-state")

    channel_names = tuple(sig.split("(", 1)[0].removeprefix("public.") for sig in channel_sigs)
    channel_defs = literal_operator_definitions(safe_read(channel_source, max_bytes=2 * 1024 * 1024),
                                                 5, channel_names)
    channel_baseline = function_map(evidence, pre_channel_access_capture)
    if any(signature not in channel_baseline for signature in channel_sigs):
        raise Rejected("pre-channel phase reference rows are incomplete")
    current_capture = fixture.capture_catalog(DATABASES["target"], "s4-target-before-channel-reset")
    current_functions = function_map(evidence, current_capture)
    for signature in channel_sigs:
        fixture.apply_script(
            DATABASES["target"],
            restore_function_capture_row_sql(signature, channel_baseline[signature],
                                             current_functions[signature]),
            "restore-pre-channel-row-" + re.sub(r"[^a-z0-9]+", "-", signature.lower())[:36],
        )
    assert_function_rows(fixture, pre_channel_access_capture, channel_sigs,
                         "prepare-product-channels-from-pre-channel-reference")
    channel_new_capture = fixture.capture_catalog(DATABASES["referenceNew"], "s4-reference-final-product-channel-state")
    channel_new_functions = function_map(evidence, channel_new_capture)
    mixed_channel = channel_sigs[0]
    fixture.apply_script(DATABASES["target"],
                         restore_function_capture_row_sql(mixed_channel, channel_new_functions[mixed_channel],
                                                          channel_baseline[mixed_channel]),
                         "make-product-channels-mixed-with-complete-new-row")
    mixed_channel_capture = fixture.capture_catalog(DATABASES["target"], "s4-target-channel-mixed-state")
    channel_expected_mixed = dict(channel_baseline)
    channel_expected_mixed[mixed_channel] = channel_new_functions[mixed_channel]
    assert_capture_function_rows(mixed_channel_capture, channel_expected_mixed, channel_sigs,
                                 "one-complete-new-channel-and-four-old-channels")
    channel_mixed_denial = expected_operator_denial(
        fixture, operator=channel_operator, label="product-channels-mixed-denial",
        expected_error="mixed channel catalog state rejected")
    mixed_channel_capture = fixture.capture_catalog(DATABASES["target"], "s4-target-channel-mixed-before-restore")
    mixed_channel_actual = function_map(evidence, mixed_channel_capture)
    fixture.apply_script(DATABASES["target"],
                         restore_function_capture_row_sql(mixed_channel, channel_baseline[mixed_channel],
                                                          mixed_channel_actual[mixed_channel]),
                         "restore-complete-old-channel-row-after-mixed")
    assert_function_rows(fixture, pre_channel_access_capture, channel_sigs,
                         "restore-product-channels-mixed")

    first_channel = channel_sigs[0]
    channel_drift_grantee = acl_drift_grantee(channel_baseline[first_channel])
    fixture.apply_script(DATABASES["target"],
                         ("GRANT EXECUTE ON FUNCTION " + first_channel + " TO "
                          + channel_drift_grantee + ";\n").encode(),
                         "make-channel-root-acl-drift")
    channel_drift_denial = expected_operator_denial(
        fixture, operator=channel_operator, label="product-channels-acl-drift-denial",
        expected_error="unexpected channel root definition/ACL")
    fixture.apply_script(DATABASES["target"],
                         ("REVOKE EXECUTE ON FUNCTION " + first_channel + " FROM "
                          + channel_drift_grantee + ";\n").encode(),
                         "restore-channel-root-acl-after-drift")
    assert_function_rows(fixture, pre_channel_access_capture, channel_sigs, "restore-product-channel-acl-drift")
    channel_first = fixture.psql(DATABASES["target"], source_path=channel_operator,
                                 label="product-channels-all-old-transition",
                                 catalog_search_path=True)
    channel_second = fixture.psql(DATABASES["target"], source_path=channel_operator,
                                  label="product-channels-all-new-idempotency",
                                  catalog_search_path=True)
    if channel_first["returnCode"] != 0 or channel_second["returnCode"] != 0:
        raise Rejected("product-channel operator did not accept all-old then all-new state")

    final_channel_capture = fixture.capture_catalog(DATABASES["referenceNew"], "s4-reference-new-post-channel")
    assert_function_rows(fixture, final_channel_capture, channel_sigs,
                         "product-channel-transition-matches-post-channel-reference")

    return {
        "ownerStateDenialMatrix": owner_matrix,
        "operators": {
            "helperSeal": {"allOldTransition": helper_first["returnCode"], "allNewIdempotent": helper_second["returnCode"],
                            "mixedDenial": helper_mixed_denial, "driftDenial": helper_drift_denial,
                            "modifiedBodyDenial": helper_body_denial},
            "threeRoots": {"allOldTransition": roots_first["returnCode"], "allNewIdempotent": roots_second["returnCode"],
                           "mixedDenial": roots_mixed_denial, "driftDenial": roots_drift_denial,
                           "modifiedBodyDenial": roots_body_denial},
            "productChannels": {"allOldTransition": channel_first["returnCode"], "allNewIdempotent": channel_second["returnCode"],
                                "mixedDenial": channel_mixed_denial, "driftDenial": channel_drift_denial},
        },
        "productAccessSha256": digest(access),
        "targetAccessCommand": target_access["label"],
        "targetOperatorOrder": ["helper-seal", "three-roots", "product-access", "product-channels"],
        "idempotencyAndMixedDriftEvidence": True,
    }


def sql_text_array(values: tuple[str, ...]) -> str:
    if any(type(value) is not str or "\x00" in value for value in values):
        raise Rejected("unsafe SQL text-array value")
    return "ARRAY[" + ",".join("'" + value.replace("'", "''") + "'" for value in values) + "]::text[]"


def build_role_probe_sql(typed_signatures: tuple[str, ...], scalar_signatures: tuple[str, ...]) -> bytes:
    v3_tables = sql_text_array(V3_TABLES)
    parent_tables = sql_text_array((
        "public.session_metadata", "public.remote_session_binding",
        "public.remote_account_identity", "public.mobile_session",
    ))
    typed = sql_text_array(typed_signatures)
    scalar = sql_text_array(scalar_signatures)
    sql = f"""SELECT json_build_object(
 'sessionUser',session_user::text,
 'currentUser',current_user::text,
 'role',(SELECT json_build_object(
   'login',r.rolcanlogin,'inherit',r.rolinherit,'super',r.rolsuper,
   'createRole',r.rolcreaterole,'createDb',r.rolcreatedb,
   'replication',r.rolreplication,'bypassRls',r.rolbypassrls,'config',r.rolconfig)
   FROM pg_roles r WHERE r.rolname=current_user),
 'memberships',(SELECT count(*) FROM pg_auth_members m
   WHERE m.member=(SELECT oid FROM pg_roles WHERE rolname=current_user)
      OR m.roleid=(SELECT oid FROM pg_roles WHERE rolname=current_user)),
 'publicUsage',has_schema_privilege(current_user,'public','USAGE'),
 'publicCreate',has_schema_privilege(current_user,'public','CREATE'),
 'assertionTypeUsage',coalesce(has_type_privilege(current_user,'public.lomi_consumer_assertion_v2','USAGE'),false),
 'typedExec',(SELECT coalesce(json_agg(json_build_object('signature',s,'allowed',has_function_privilege(current_user,s,'EXECUTE')) ORDER BY s),'[]'::json)
    FROM unnest({typed}) AS q(s)),
 'scalarExec',(SELECT coalesce(json_agg(json_build_object('signature',s,'allowed',has_function_privilege(current_user,s,'EXECUTE')) ORDER BY s),'[]'::json)
    FROM unnest({scalar}) AS q(s)),
 'tables',(SELECT coalesce(json_agg(json_build_object(
    'name',t,
    'select',coalesce(has_table_privilege(current_user,t,'SELECT'),false),
    'insert',coalesce(has_table_privilege(current_user,t,'INSERT'),false),
    'update',coalesce(has_table_privilege(current_user,t,'UPDATE'),false),
    'delete',coalesce(has_table_privilege(current_user,t,'DELETE'),false),
    'anySelect',coalesce(has_any_column_privilege(current_user,t,'SELECT'),false),
    'anyInsert',coalesce(has_any_column_privilege(current_user,t,'INSERT'),false),
    'anyUpdate',coalesce(has_any_column_privilege(current_user,t,'UPDATE'),false),
    'anyReferences',coalesce(has_any_column_privilege(current_user,t,'REFERENCES'),false)) ORDER BY t),'[]'::json)
    FROM unnest({v3_tables}) AS q(t)),
 'columns',(SELECT coalesce(json_agg(json_build_object(
    'table',c.relname,'column',a.attname,
    'select',coalesce(has_column_privilege(current_user,c.oid,a.attname,'SELECT'),false),
    'insert',coalesce(has_column_privilege(current_user,c.oid,a.attname,'INSERT'),false),
    'update',coalesce(has_column_privilege(current_user,c.oid,a.attname,'UPDATE'),false),
    'references',coalesce(has_column_privilege(current_user,c.oid,a.attname,'REFERENCES'),false))
      ORDER BY c.relname,a.attnum),'[]'::json)
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
    WHERE n.nspname='public' AND c.relname IN
      ('consumer_authorization','consumer_approval_intent','consumer_approval_consumed_proof','consumer_derivative_consent',
       'session_metadata','remote_session_binding','remote_account_identity','mobile_session')),
 'parentTables',(SELECT coalesce(json_agg(json_build_object(
    'name',t,'select',coalesce(has_table_privilege(current_user,t,'SELECT'),false),
    'insert',coalesce(has_table_privilege(current_user,t,'INSERT'),false),
    'update',coalesce(has_table_privilege(current_user,t,'UPDATE'),false),
    'delete',coalesce(has_table_privilege(current_user,t,'DELETE'),false)) ORDER BY t),'[]'::json)
    FROM unnest({parent_tables}) AS q(t))
)::text;
"""
    return sql.encode("utf-8")


def table_row(probe: dict, name: str) -> dict:
    rows = [row for row in probe["tables"] if row["name"] == name]
    if len(rows) != 1:
        raise Rejected("role probe omitted or duplicated table: " + name)
    return rows[0]


def update_columns(probe: dict, table: str) -> list[str]:
    return sorted(row["column"] for row in probe["columns"]
                  if "public." + row["table"] == table and row["update"] is True)


def selected_columns(probe: dict, table: str) -> list[str]:
    return sorted(row["column"] for row in probe["columns"]
                  if "public." + row["table"] == table and row["select"] is True)


def bool_signature_map(probe: dict, group: str) -> dict[str, bool]:
    rows = probe[group]
    if type(rows) is not list or any(set(row) != {"signature", "allowed"} for row in rows):
        raise Rejected("effective function privilege probe shape")
    result = {row["signature"]: row["allowed"] for row in rows}
    if len(result) != len(rows):
        raise Rejected("duplicate effective function privilege probe")
    return result


def run_role_probe(fixture: Fixture, *, role: str, typed: tuple[str, ...],
                   scalar: tuple[str, ...], login: bool) -> dict:
    query = build_role_probe_sql(typed, scalar)
    if login:
        user = role
        script = query
    else:
        user = "e2_owner"
        script = ("SET ROLE " + role + ";\n").encode("ascii") + query
    result = fixture.psql(DATABASES["target"], user=user, script=script,
                          label="s5-role-probe-" + role, timeout=25)
    try:
        probe = strict_json(result["stdout"].strip(), "effective role probe")
    except Rejected:
        raise Rejected("role probe output is not one JSON row: " + role)
    if probe.get("currentUser") != role or probe.get("sessionUser") != (role if login else "e2_owner"):
        raise Rejected("role probe did not execute in the requested database role: " + role)
    attrs = probe.get("role")
    if type(attrs) is not dict or attrs.get("login") is not login:
        raise Rejected("role login attribute differs from fixture contract: " + role)
    if (attrs.get("super") is not False or attrs.get("createRole") is not False
            or attrs.get("createDb") is not False or attrs.get("replication") is not False
            or attrs.get("bypassRls") is not False or attrs.get("inherit") is not False
            or attrs.get("config") is not None or probe.get("memberships") != 0):
        raise Rejected("role retains an unapproved attribute, configuration, or membership: " + role)
    if type(probe.get("publicUsage")) is not bool or probe.get("publicCreate") is not False:
        raise Rejected("role public schema USAGE/CREATE boundary mismatch: " + role)
    expected_tables = set(V3_TABLES)
    if {row.get("name") for row in probe.get("tables", [])} != expected_tables:
        raise Rejected("role probe table closure mismatch: " + role)
    if set(bool_signature_map(probe, "typedExec")) != set(typed):
        raise Rejected("typed function privilege closure mismatch: " + role)
    if set(bool_signature_map(probe, "scalarExec")) != set(scalar):
        raise Rejected("scalar function privilege closure mismatch: " + role)
    return probe


def assert_role_acl_matrix(probes: dict[str, dict], typed: tuple[str, ...], scalar: tuple[str, ...]):
    api, runtime, exchange = probes["lomi_remote_api"], probes["lomi_runtime"], probes["lomi_remote_exchange"]
    pairing = probes["lomi_remote_pairing_write_owner"]
    inventory = probes["lomi_remote_inventory_owner"]
    body = probes["lomi_consumer_auth_body_owner"]
    host_runtime = probes["lomi_remote_runtime_owner"]

    for role_name, probe in probes.items():
        typed_map = bool_signature_map(probe, "typedExec")
        scalar_map = bool_signature_map(probe, "scalarExec")
        if role_name == "lomi_remote_api":
            if any(typed_map.values()) is False or not all(typed_map.values()):
                raise Rejected("Remote API lacks one or more typed wrapper EXECUTE grants")
            if any(scalar_map.values()):
                raise Rejected("Remote API retains scalar consumer EXECUTE")
            if probe["assertionTypeUsage"] is not True:
                raise Rejected("Remote API lacks assertion type USAGE")
            for table in V3_TABLES:
                if any(table_row(probe, table)[flag] for flag in ("select", "insert", "update", "delete", "anySelect", "anyInsert", "anyUpdate", "anyReferences")):
                    raise Rejected("Remote API has direct Consumer v3 table/column privileges")
        elif role_name == "lomi_remote_pairing_write_owner":
            if not all(typed_map.values()) or not all(scalar_map.values()) or probe["assertionTypeUsage"] is not True:
                raise Rejected("pairing owner lacks internal typed/scalar/type access")
            for table in V3_TABLES:
                if any(table_row(probe, table)[flag] for flag in ("select", "insert", "update", "delete", "anySelect", "anyInsert", "anyUpdate", "anyReferences")):
                    raise Rejected("pairing owner has direct Consumer v3 table access")
        elif role_name == "lomi_remote_inventory_owner":
            if any(typed_map.values()) or any(scalar_map.values()) or not probe["assertionTypeUsage"]:
                raise Rejected("inventory owner typed/scalar public wrapper boundary mismatch")
        elif role_name in ("lomi_runtime", "lomi_remote_exchange", "lomi_remote_runtime_owner"):
            if any(typed_map.values()) or probe["assertionTypeUsage"]:
                raise Rejected("Runtime, Exchange, or host owner has assertion type/typed wrapper access")
            if role_name in ("lomi_remote_exchange", "lomi_remote_runtime_owner") and any(scalar_map.values()):
                raise Rejected("Exchange or host owner retains scalar consumer EXECUTE")
            if role_name == "lomi_remote_runtime_owner":
                for table in V3_TABLES:
                    if any(table_row(probe, table)[flag] for flag in ("select", "insert", "update", "delete", "anySelect", "anyInsert", "anyUpdate", "anyReferences")):
                        raise Rejected("host runtime owner has direct Consumer v3 table access")
        elif role_name == "lomi_consumer_auth_body_owner":
            if probe["assertionTypeUsage"] or any(typed_map.values()) or any(scalar_map.values()):
                raise Rejected("sealed body owner has direct type or consumer function access")
            for table in V3_TABLES:
                if any(table_row(probe, table)[flag] for flag in ("select", "insert", "update", "delete", "anySelect", "anyInsert", "anyUpdate", "anyReferences")):
                    raise Rejected("sealed body owner has table/column privileges")

    # Verify table grants independently from column-level updates. Exchange
    # consumes approval intent but is not allowed to create it; Runtime owns
    # issuance and is the only writer of authorization/consent revocation.
    runtime_expect = {
        "public.consumer_authorization": (True, True, False, False, ["revoked"]),
        "public.consumer_approval_intent": (True, True, False, False, ["consumedAt"]),
        "public.consumer_approval_consumed_proof": (True, True, False, False, []),
        "public.consumer_derivative_consent": (True, True, False, False, ["revoked"]),
    }
    exchange_expect = {
        "public.consumer_authorization": (False, False, False, False, []),
        "public.consumer_approval_intent": (True, False, False, False, ["consumedAt"]),
        "public.consumer_approval_consumed_proof": (True, True, False, False, []),
        "public.consumer_derivative_consent": (True, True, False, False, []),
    }
    for role_name, expected in (("lomi_runtime", runtime_expect), ("lomi_remote_exchange", exchange_expect)):
        probe = probes[role_name]
        for table, (select, insert, update, delete, permitted_updates) in expected.items():
            row = table_row(probe, table)
            if (row["select"], row["insert"], row["update"], row["delete"]) != (select, insert, update, delete):
                raise Rejected("Runtime/Exchange table-level ACL boundary mismatch: " + table)
            if update_columns(probe, table) != permitted_updates:
                raise Rejected("Runtime/Exchange column UPDATE allowlist mismatch: " + table)

    if selected_columns(exchange, "public.mobile_session") != ["consumerApprovalId", "id"]:
        raise Rejected("Exchange mobile-session read is broader than the opposite-kind gate")
    required_parent_reads = EXCHANGE_PARENT_READ_COLUMNS
    for table, expected_columns in required_parent_reads.items():
        if selected_columns(exchange, table) != expected_columns:
            raise Rejected("Exchange parent-read column set mismatch: " + table)

    inventory_expect = {
        "public.consumer_authorization": (True, False, False, False),
        "public.consumer_approval_intent": (False, False, False, False),
        "public.consumer_approval_consumed_proof": (False, False, False, False),
        "public.consumer_derivative_consent": (True, False, False, False),
    }
    for table, expected in inventory_expect.items():
        row = table_row(inventory, table)
        if (row["select"], row["insert"], row["update"], row["delete"]) != expected:
            raise Rejected("inventory owner table-level ACL boundary mismatch: " + table)
        if any(row[key] for key in ("anyInsert", "anyUpdate", "anyReferences")):
            raise Rejected("inventory owner has a forbidden Consumer v3 column privilege: " + table)
    for table in ("public.consumer_approval_intent", "public.consumer_approval_consumed_proof"):
        if not selected_columns(inventory, table):
            raise Rejected("inventory owner lacks the required narrow retained-row read: " + table)

    for table in ("public.consumer_authorization", "public.consumer_derivative_consent"):
        row = table_row(inventory, table)
        if row["select"] is not True or row["insert"] or row["update"] or row["delete"]:
            raise Rejected("inventory owner C/consent read boundary mismatch")
    for table in V3_TABLES:
        if table not in ("public.consumer_authorization", "public.consumer_derivative_consent"):
            if any(table_row(inventory, table)[key] for key in ("insert", "update", "delete")):
                raise Rejected("inventory owner has unexpected Consumer v3 write access")
    return {"apiTypedWrappers": len(typed), "apiScalarConsumers": 0,
            "runtimeConsumerUpdateColumns": runtime_expect,
            "exchangeConsumerUpdateColumns": exchange_expect,
            "exchangeParentReadColumns": required_parent_reads,
            "exchangeMobileSessionSelectColumns": ["consumerApprovalId", "id"],
            "bodyOwnerNoDirectAccess": True}


def deny_as_role(fixture: Fixture, role: str, sql: str, label: str, *, login: bool):
    script = "\\set VERBOSITY verbose\n" + (("" if login else "SET ROLE " + role + ";\n")) + sql.rstrip(";\n") + ";\n"
    result = fixture.psql(DATABASES["target"], user=role if login else "e2_owner",
                          script=script.encode("utf-8"), label=label,
                          expected=(3,), timeout=20)
    data = result["stderr"] + b"\n" + result["stdout"]
    if b"42501" not in data:
        raise Rejected("negative ACL probe did not return PostgreSQL 42501: " + label)
    return {"role": role, "label": label, "sqlstate": "42501",
            "stderrSha256": result["stderrSha256"]}


def assert_host_parent_relations(baseline_rows, final_rows):
    """Preserve complete host/parent rows except nine reviewed column grants.

    Do not strip ACLs or parent relations from the comparison. Derive the exact
    expected final rows from the independently migrated active baseline, adding
    only fixture-product-access.sql's nongrantable Exchange SELECT entries.
    Catalog ACL array order uses role OIDs, which is not privilege semantics.
    """
    def relations(rows):
        result = {}
        for row in rows:
            if row.get("kind") != "relation":
                continue
            name = row.get("relation", "")
            if not (name.removeprefix("public.").startswith("host_")
                    or name in EXCHANGE_PARENT_READ_COLUMNS):
                continue
            if name in result:
                raise Rejected("duplicate host/identity parent relation capture")
            result[name] = json.loads(json.dumps(row, ensure_ascii=False))
        return result

    expected = relations(baseline_rows)
    final = relations(final_rows)
    for relation, columns in EXCHANGE_PARENT_READ_COLUMNS.items():
        if relation not in expected or expected[relation].get("owner") != "lomi_migrator":
            raise Rejected("missing or unexpected owner for baseline parent relation")
        by_name = {column["name"]: column for column in expected[relation]["columns"]}
        for name in columns:
            if name not in by_name:
                raise Rejected("missing baseline Exchange parent-read column")
            acl = by_name[name]["acl"]
            if any(entry["grantee"] == "lomi_remote_exchange" for entry in acl):
                raise Rejected("unexpected baseline Exchange parent column ACL")
            acl.append({"grantor": "lomi_migrator", "grantee": "lomi_remote_exchange",
                        "privilege": "SELECT", "grantable": False})
    # Compare all relation properties, including table ACLs, column definitions,
    # and every grantor/grantee/privilege/grant-option entry. Only array order
    # inside a column ACL is immaterial; duplicate entries remain detectable.
    for rows in (expected, final):
        for row in rows.values():
            for column in row["columns"]:
                column["acl"].sort(key=lambda value: json.dumps(value, sort_keys=True))
    if expected != final:
        raise Rejected("existing host/identity parent relation schema or ACL changed outside exact Exchange column grants")
    return {"hostAndParentSchemaUnchanged": True,
            "parentAclDelta": {"grantee": "lomi_remote_exchange", "grantor": "lomi_migrator",
                               "privilege": "SELECT", "grantable": False,
                               "columns": EXCHANGE_PARENT_READ_COLUMNS}}


def run_s5_role_and_acl_checks(fixture: Fixture, active_reference_old: bytes, operator_evidence: dict):
    frozen = PACKAGE / "inputs/frozen-v3-successor"
    product_contract = strict_json(
        safe_read(PACKAGE / "channel-transition.pending.json", max_bytes=512 * 1024),
        "product channel contract",
    )
    typed = tuple(row["signature"] for row in product_contract["prerequisites"]
                  if "_v2(" in row["signature"]
                  and "public.lomi_consumer_assertion_v2" in row["signature"]
                  and "lomi_consumer_assertion_v2_recheck" not in row["signature"])
    if len(typed) != 15 or len(set(typed)) != 15:
        raise Rejected("S5 requires exactly fifteen base+window typed wrappers")
    scalar = RETIRED_SCALAR_SIGNATURES
    probe_roles = {
        "lomi_remote_api": True,
        "lomi_runtime": True,
        "lomi_remote_exchange": True,
        "lomi_remote_inventory_owner": False,
        "lomi_remote_pairing_write_owner": False,
        "lomi_consumer_auth_body_owner": False,
        "lomi_remote_runtime_owner": False,
    }
    probes = {role: run_role_probe(fixture, role=role, typed=typed, scalar=scalar, login=login)
              for role, login in probe_roles.items()}
    matrix = assert_role_acl_matrix(probes, typed, scalar)
    denials = [
        deny_as_role(fixture, "lomi_remote_api", "CREATE TABLE public.lomi_acl_probe_api(id integer)", "api-public-create-denial", login=True),
        deny_as_role(fixture, "lomi_remote_api", "SELECT * FROM public.consumer_authorization LIMIT 0", "api-c-direct-read-denial", login=True),
        deny_as_role(fixture, "lomi_remote_api", "SELECT public.lomi_consumer_inventory(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)", "api-scalar-consumer-denial", login=True),
        deny_as_role(fixture, "lomi_runtime", "DELETE FROM public.consumer_authorization WHERE false", "runtime-c-delete-denial", login=True),
        deny_as_role(fixture, "lomi_runtime", "UPDATE public.consumer_authorization SET \"accountId\"=\"accountId\" WHERE false", "runtime-c-snapshot-update-denial", login=True),
        deny_as_role(fixture, "lomi_runtime", "UPDATE public.consumer_approval_consumed_proof SET \"proofVersion\"=\"proofVersion\" WHERE false", "runtime-proof-update-denial", login=True),
        deny_as_role(fixture, "lomi_remote_exchange", "SELECT * FROM public.consumer_authorization LIMIT 0", "exchange-c-direct-read-denial", login=True),
        deny_as_role(fixture, "lomi_remote_exchange", "UPDATE public.consumer_approval_consumed_proof SET \"proofVersion\"=\"proofVersion\" WHERE false", "exchange-proof-update-denial", login=True),
        deny_as_role(fixture, "lomi_remote_pairing_write_owner", "SELECT * FROM public.consumer_authorization LIMIT 0", "pairing-owner-c-direct-read-denial", login=False),
        deny_as_role(fixture, "lomi_consumer_auth_body_owner", "CREATE TABLE public.lomi_acl_probe_body(id integer)", "body-owner-schema-create-denial", login=False),
        deny_as_role(fixture, "lomi_consumer_auth_body_owner", "SELECT * FROM public.consumer_authorization LIMIT 0", "body-owner-table-read-denial", login=False),
    ]
    # Role names and memberships are measured from raw catalog captures. This
    # source-derived exact role set rejects unplanned grantor/creator drift.
    source_sql = []
    for relative in fixture.lock["sourceAllowlist"]:
        if (relative.startswith("auth-app/ops/") and relative.endswith(".sql")) or (
                relative.startswith(PACKAGE_REL + "/") and relative.endswith(".sql")):
            source_sql.append(safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT).decode("utf-8", "strict"))
    created = {"e2_owner", "lomi_migrator", "lomi_runtime", "lomi_remote_api", "lomi_remote_exchange"}
    for text in source_sql:
        created.update(re.findall(r"\bCREATE\s+ROLE\s+([a-z_][a-z0-9_]*)", text, re.I))
    final_capture = fixture.capture_catalog(DATABASES["target"], "s5-final-catalog-closure")
    _, evidence, _ = load_local_modules()
    rows = evidence.verify_capture(final_capture)["rows"]
    measured_roles = {row["name"] for row in rows if row["kind"] == "role"}
    if measured_roles != created:
        raise Rejected("unknown or missing fixture role drift: measured role closure differs from source-derived role set")
    baseline = evidence.verify_capture(active_reference_old)
    final = evidence.verify_capture(final_capture)

    def is_host_function(signature):
        name = signature.split("(", 1)[0].removeprefix("public.lomi_")
        return name.startswith("host_") or "_host_" in name

    baseline_host = {signature: row for signature, row in baseline["functions"].items()
                     if is_host_function(signature)}
    final_host = {signature: row for signature, row in final["functions"].items()
                  if is_host_function(signature)}
    if baseline_host != final_host:
        raise Rejected("existing host function definitions/owners/ACLs changed")
    parent_state = assert_host_parent_relations(baseline["rows"], final["rows"])
    helper_matrix = run_sealed_helper_denials(fixture, final_capture)
    # These strict operators are exercised at their measured sealing phases,
    # before the later product-access ACL transition, with genuine controls.
    owner_state_matrix = operator_evidence["ownerStateDenialMatrix"]
    if (owner_state_matrix.get("attemptCount") != 28 or owner_state_matrix.get("deniedCount") != 28
            or owner_state_matrix.get("fullOwnerStateDenialMatrixValidated") is not True):
        raise Rejected("complete phase-bound owner-state denial evidence is missing")
    return {"effectiveRoleProbes": probes, "roleMatrix": matrix, "negativeAclChecks": denials,
            "measuredRoles": sorted(measured_roles), "roleMembershipsMeasured": True,
            "defaultsAndExpandedAclsMeasured": True,
            "allRolesExecutedAsTheirActualCurrentUser": True,
            "noOwnerApplicationCalls": True,
            "hostFunctionStateUnchanged": True,
            "hostAndParentRelationState": parent_state,
            "sealedHelperDenialMatrix": helper_matrix,
            "operatorOwnerStateDenialMatrix": owner_state_matrix,
            "boundedAclSubsetQualified": True,
            "fullS5Qualified": True,
            "fullS5Missing": []}


def run_sealed_helper_denials(fixture: Fixture, initial_capture: bytes):
    # The admission gate verifies this adjacent module as data before import.
    sys.path.insert(0, str(HERE))
    import helper_denials
    _, evidence, _ = load_local_modules()
    outcomes = []
    capture_hashes = []
    before = initial_capture
    for index, attempt in enumerate(helper_denials.build_attempts(fixture.run_id)):
        if attempt["connectionRole"] != attempt["role"]:
            raise Rejected("helper denial must use its actual nonoperator LOGIN")
        label = f"s5-helper-denial-{index:03d}"
        result = fixture.psql(
            DATABASES["target"], user=attempt["connectionRole"],
            script=attempt["sql"].encode("utf-8"), label=label,
            expected=(0,), timeout=20,
        )
        after = fixture.capture_catalog(DATABASES["target"], label + "-after")
        if not evidence.stable_catalog_equality(before, after):
            raise Rejected("helper denial changed database catalog or role state")
        outcome = {
            "attemptId": attempt["attemptId"],
            "processReturnCode": result["returnCode"],
            "output": result["stderr"] + b"\n" + result["stdout"],
            "beforeCapture": before, "afterCapture": after,
        }
        helper_denials.validate_attempt_result(
            attempt, process_return_code=outcome["processReturnCode"],
            output=outcome["output"], before_capture=before, after_capture=after,
        )
        outcomes.append(outcome)
        capture_hashes.append({"attemptId": attempt["attemptId"],
                               "beforeSha256": digest(before), "afterSha256": digest(after),
                               "stdoutSha256": result["stdoutSha256"],
                               "stderrSha256": result["stderrSha256"]})
        before = after
    return {**helper_denials.validate_complete_matrix(fixture.run_id, outcomes),
            "captureHashes": capture_hashes,
            "allConnectionsUsedActualNonoperatorLogin": True,
            "entireCatalogAndRolesUnchangedAfterEveryRollback": True}


def owner_state_parameters(fixture: Fixture, operator_evidence: dict):
    # Import occurs only after every adjacent module passed the source gate.
    sys.path.insert(0, str(HERE))
    import owner_state_denials
    source_names = {"helperSeal": "operator-helper-seal.private.sql",
                    "threeRoots": "operator-three-roots.private.sql"}
    sources = {name: safe_read(fixture.work / "sql" / relative, max_bytes=2 * 1024 * 1024)
               for name, relative in source_names.items()}
    source_hashes = {name: fixture.filled_operators[name]["filledSha256"] for name in source_names}
    controls = {
        name: {"operatorSha256": source_hashes[name],
               "allOldTransition": operator_evidence["operators"][name]["allOldTransition"],
               "allNewIdempotent": operator_evidence["operators"][name]["allNewIdempotent"]}
        for name in operator_evidence["operators"]
    }
    parameters = {"operator_sources": sources, "expected_operator_sha256": source_hashes,
                  "positive_controls": controls}
    return owner_state_denials, parameters


def run_owner_state_denials(fixture: Fixture, operator_evidence: dict,
                            *, operator_ids=("helperSeal", "threeRoots")):
    owner_state_denials, parameters = owner_state_parameters(fixture, operator_evidence)
    parameters = {**parameters, "operator_ids": operator_ids}
    attempts = owner_state_denials.build_attempts(fixture.run_id, **parameters)
    phase = "-".join(operator_ids)
    before = fixture.capture_catalog(DATABASES["target"], "s5-before-owner-state-" + phase)
    outcomes = []
    log_hashes = []
    for index, attempt in enumerate(attempts):
        label = f"s5-owner-state-{phase}-{index:03d}"
        result = fixture.psql(
            DATABASES["target"], user="e2_owner", script=attempt["sql"].encode("utf-8"),
            label=label, catalog_search_path=True, expected=(0,), timeout=20,
        )
        after = fixture.capture_catalog(DATABASES["target"], label + "-after")
        output = result["stderr"] + b"\n" + result["stdout"]
        owner_state_denials.validate_attempt_result(
            attempt, process_return_code=result["returnCode"], output=output,
            before_capture=before, after_capture=after, **parameters,
        )
        outcomes.append({"attemptId": attempt["attemptId"], "processReturnCode": result["returnCode"],
                         "output": output, "beforeCapture": before, "afterCapture": after})
        log_hashes.append({"attemptId": attempt["attemptId"], "stdoutSha256": result["stdoutSha256"],
                           "stderrSha256": result["stderrSha256"]})
        before = after
    return ({**owner_state_denials.validate_complete_matrix(fixture.run_id, outcomes, **parameters),
             "logHashes": log_hashes,
             "mutationsConfinedToPrivateOperatorRollbackTransactions": True}, outcomes)


def run_s6_actual_handler_test(fixture: Fixture) -> dict:
    project = fixture.work / "bun-project"
    if project.is_symlink() or not project.is_dir():
        raise Rejected("private Bun project directory is missing")
    copy_paths = [
        name for name in fixture.lock["sourceAllowlist"]
        if name.startswith("auth-app/src/")
    ] + [
        "auth-app/package.json",
        "auth-app/bun.lock",
        "auth-app/tsconfig.json",
        "auth-app/test/runtime-privacy.ts",
        "auth-app/test/consumer-derivative-product-runtime.test.ts",
        "auth-app/test/consumer-derivative-positive-transactions.ts",
        "auth-app/test/consumer-derivative-positive-cleanup.ts",
    ]
    for relative in sorted(copy_paths):
        if relative not in fixture.lock["sourceAllowlist"]:
            raise Rejected("actual-handler runtime source is not pinned: " + relative)
        destination = project / relative.removeprefix("auth-app/")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.parent.is_symlink() or destination.exists() or destination.is_symlink():
            raise Rejected("private Bun runtime copy path already exists")
        write_new(destination, safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT))
    module_dir = project / "node_modules"
    if module_dir.exists() or module_dir.is_symlink():
        raise Rejected("private Bun dependency link already exists")
    expected_modules = str(WORKSPACE / "auth-app/node_modules")
    if expected_modules != fixture.lock.get("runtimeDependencyPath"):
        raise Rejected("runtime dependency path is not the reviewed Auth installation")
    os.symlink(expected_modules, module_dir)
    if os.readlink(module_dir) != expected_modules:
        raise Rejected("private Bun dependency link target drift")
    tool_before = verify_toolchain(fixture.lock)
    env = s6_private_environment(fixture.work, str(fixture.work / "socket"))
    if any(key in env for key in ("DATABASE_URL", "DIRECT_URL", "PGHOST", "PGUSER")):
        raise Rejected("S6 environment contains ambient database fallback")
    result = fixture.command(
        "consumer-v3-actual-handler-runtime",
        [str(fixture.bun), "--no-env-file", "test", "--timeout", "180000",
         "--max-concurrency", "1", "test/consumer-derivative-product-runtime.test.ts"],
        timeout=210,
        output_limit=PROCESS_OUTPUT_LIMIT,
        cwd=project,
        env=env,
    )
    _, evidence, _ = load_local_modules()
    acceptance = evidence.parse_s6_acceptance(result["stdout"])
    tool_after = verify_toolchain(fixture.lock)
    if tool_before != tool_after:
        raise Rejected("runtime tool or dependency bytes changed during S6")
    return {
        "status": "PASS",
        "acceptedAssertions": acceptance,
        "actualHandlerFlowQualificationOnly": True,
        "realRelayAndClientProductAcceptance": "NOT_CLAIMED",
        "pairingChannelTicketTransactions": "PASS",
        "sourceHashes": {
            relative: digest(safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT))
            for relative in copy_paths
        },
        "dependencyTreeSha256": tool_after["runtimeDependencyTreeSha256"],
        "bunSha256": tool_after["bunSha256"],
        "stdoutSha256": result["stdoutSha256"],
        "stderrSha256": result["stderrSha256"],
        "returnCode": result["returnCode"],
    }


def run_s7_populated_runtime(fixture: Fixture) -> dict:
    # Local modules have already passed the bundle's exact pre-import source
    # gate. No arbitrary specification or target URL is accepted here.
    import s7_spec
    import s7_evidence

    source_hashes = {}
    for relative in s7_spec.SOURCE_HASH_PATHS:
        expected = fixture.lock["sourceAllowlist"].get(relative)
        raw = safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT)
        if expected is None or digest(raw) != expected:
            raise Rejected("S7 source pin missing or changed: " + relative)
        source_hashes[relative] = expected
    spec = s7_spec.build_spec(source_hashes)
    source_root = fixture.work / "s7-sources"
    os.mkdir(source_root, 0o700)
    for relative in s7_spec.SOURCE_HASH_PATHS:
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(destination, safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT),
                  mode=0o400)
    plan_raw = _json_bytes(spec)
    write_new(fixture.work / "s7-plan.json", plan_raw)
    write_new(fixture.run_dir / "s7-plan.json", plan_raw)

    project = fixture.work / "bun-project"
    for relative in (
        "auth-app/test/consumer-derivative-populated-runtime.ts",
        "auth-app/test/consumer-derivative-populated-product-runtime.test.ts",
    ):
        expected = fixture.lock["sourceAllowlist"].get(relative)
        raw = safe_read(source_input(relative), max_bytes=CATALOG_OUTPUT_LIMIT)
        if expected is None or digest(raw) != expected:
            raise Rejected("S7 executable source missing or changed")
        write_new(project / relative.removeprefix("auth-app/"), raw)

    tool_before = verify_toolchain(fixture.lock)
    result = fixture.command(
        "consumer-v3-populated-runtime",
        [str(fixture.bun), "--no-env-file", "test", "--timeout", "420000",
         "--max-concurrency", "1", "test/consumer-derivative-populated-product-runtime.test.ts"],
        timeout=450, expected=(0, 1), output_limit=PROCESS_OUTPUT_LIMIT,
        cwd=project, env=s7_private_environment(fixture.work, str(fixture.work / "socket")),
    )
    output_path = fixture.work / "s7-output.json"
    info = output_path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid() or info.st_nlink != 1):
        raise Rejected("S7 private output metadata drift")
    output_raw = safe_read(output_path, max_bytes=32 * 1024 * 1024)
    # Preserve private evidence even when the Bun test or postvalidator rejects
    # it. The outer controller still owns database shutdown and tree cleanup.
    write_new(fixture.run_dir / "s7-runtime-output.json", output_raw)
    output = strict_json(output_raw, "S7 private runtime output")
    if type(output) is not dict or set(output) != {"evidence", "privateSeedReceipts"}:
        raise Rejected("S7 output envelope differs from the fixed contract")
    if (result["returnCode"] != 0 or result["stdout"].splitlines().count(
            b"LOMI_CONSUMER_V3_S7_DRIVER_COMPLETED") != 1):
        raise Rejected("S7 runtime did not complete; private observations retained")
    validated = s7_evidence.validate_runtime_evidence(
        output["evidence"], output["privateSeedReceipts"], spec)
    tool_after = verify_toolchain(fixture.lock)
    if tool_before != tool_after:
        raise Rejected("runtime tool or dependency bytes changed during S7")
    return {
        **validated,
        "sourceHashes": source_hashes,
        "querySpecificationSha256": spec["querySpecificationSha256"],
        "runtimeOutputSha256": digest(output_raw),
        "runtimeOutputBytes": len(output_raw),
        "dependencyTreeSha256": tool_after["runtimeDependencyTreeSha256"],
        "bunSha256": tool_after["bunSha256"],
        "stdoutSha256": result["stdoutSha256"],
        "stderrSha256": result["stderrSha256"],
        "returnCode": result["returnCode"],
        "realRelayAndClientProductAcceptance": "NOT_CLAIMED",
    }


def _json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _toolchain_fingerprint(result: dict) -> str:
    return digest(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def create_private_run_directory(run_id: str) -> Path:
    artifact_root = PROJECT / "artifacts"
    if (artifact_root.is_symlink() or not artifact_root.is_dir()
            or artifact_root.resolve() != artifact_root):
        raise Rejected("private artifact root unavailable")
    info = artifact_root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise Rejected("private artifact root ownership mismatch")
    path = artifact_root / ("consumer-derivatives-v3-product-run-" + run_id)
    os.mkdir(path, 0o700)
    private_dir(path, uid=os.getuid())
    return path


def source_hash_snapshot(lock: dict) -> dict[str, str]:
    return {name: file_digest(WORKSPACE / name) for name in sorted(lock["sourceAllowlist"])}


def _deadline_handler(signum, frame):
    raise DeadlineExpired("original 900-second fixture deadline expired")


def run_qualification() -> int:
    started = time.monotonic()
    work_deadline = started + WORK_DEADLINE
    final_deadline = started + ORIGINAL_DEADLINE
    run_id = str(uuid.uuid4())
    stages = {f"S{i}": "NOT_RUN" for i in range(8)}
    stage_evidence = {}
    stage_details = {}
    fixture = None
    work = Path("/tmp") / ("lomi-e2-" + run_id)
    run_dir = None
    preflight = None
    source_after = {"status": SOURCE_AFTER_FAILURE_STATUS}
    error = None
    cleanup_evidence = {"completed": False, "status": "NOT_STARTED"}
    old_handlers = {}
    try:
        if not hasattr(signal, "setitimer"):
            raise Rejected("monotonic interval deadline support required")
        old_handlers[signal.SIGALRM] = signal.signal(signal.SIGALRM, _deadline_handler)
        old_handlers[signal.SIGINT] = signal.signal(signal.SIGINT, _deadline_handler)
        old_handlers[signal.SIGTERM] = signal.signal(signal.SIGTERM, _deadline_handler)
        signal.setitimer(signal.ITIMER_REAL, max(0.001, work_deadline - time.monotonic()))

        lock, manifest, controller_sha, manifest_sha, receipts, evidence, prepare = verify_bundle_and_receipts()
        preflight = run_workspace_preflight(lock, manifest)
        owned = import_owned_process()
        if work.exists() or work.is_symlink():
            raise Rejected("private UUID work path collision")
        run_dir = create_private_run_directory(run_id)
        os.mkdir(work, 0o700)
        private_dir(work, uid=os.getuid())
        tool_hashes_before = preflight["toolchain"]
        fixture = Fixture(owned, {**lock, "bundleManifestSha256": manifest_sha},
                          work, run_dir, started, work_deadline, final_deadline,
                          Path(lock["bunPath"]), Path(lock["postgresRoot"]),
                          tool_hashes_before, run_id)

        current_stage = "S0"
        cluster = fixture.create_cluster()
        stage_details["S0"] = {
            "sourceClosureSha256": digest(_json_bytes(preflight["sourceClosure"])),
            "successorPackage": preflight["package"],
            "toolchainSha256": _toolchain_fingerprint(tool_hashes_before),
            "toolchainCounts": {
                "postgresRegularFiles": len(tool_hashes_before["postgresFiles"]),
                "postgresSymlinks": len(tool_hashes_before["postgresSymlinks"]),
                "postgresDependencies": len(tool_hashes_before["postgresDependencies"]),
            },
            "actualVersions": cluster["actualVersions"],
            "socketOnlyServer": cluster["settings"],
            "maxConnections": 16,
            "realRolePools": 4,
            "maximumConnectionsPerRolePool": 2,
            "privateWorkMarkerSha256": file_digest(work / "fixture.marker.json"),
        }
        stages["S0"] = "PASS"
        stage_evidence["S0"] = True

        current_stage = "S1"
        role_evidence = create_database_roles(fixture)
        baseline_sources = apply_active_baseline(fixture)
        baseline = baseline_old_state(fixture)
        stage_details["S1"] = {
            "roles": role_evidence,
            "activeSourceReplay": baseline_sources,
            "rawBaselineCaptures": {
                name: {"sha256": digest(raw), "bytes": len(raw)}
                for name, raw in baseline.items()
            },
            "independentDatabaseComparison": {
                "targetVsReferenceOld": "PASS",
                "referenceOldVsReferenceNew": "PASS",
                "internalForeignKeyTriggersComparedByStableRelationConstraintStructure": True,
                "rawCapturesAndFunctionDefinitionBytesPreserved": True,
            },
            "syntheticPrismaLedger": False,
            "prismaLedgerQualification": "PRIVATE_FIXTURE_ACTUAL_PRISMA_ENGINE_ONLY_NOT_PRODUCTION_QUALIFICATION",
            "productionLedgerQualification": "NOT_CLAIMED",
        }
        stages["S1"] = "PASS"
        stage_evidence["S1"] = True

        current_stage = "S2"
        source_layers = execute_successor_source_layers(fixture)
        target_after_sources = fixture.capture_catalog(DATABASES["target"], "s2-target-after-source-layers")
        new_after_sources = fixture.capture_catalog(DATABASES["referenceNew"], "s2-reference-new-after-source-layers")
        if not evidence.stable_catalog_equality(target_after_sources, new_after_sources):
            raise Rejected("target and source-derived reference-new differ after candidate source layer")
        stage_details["S2"] = {
            "sourceLayers": source_layers,
            "candidateTargetVsReferenceNew": "PASS",
            "rawCaptureSha256": {
                "target": digest(target_after_sources),
                "referenceNew": digest(new_after_sources),
            },
        }
        stages["S2"] = "PASS"
        stage_evidence["S2"] = True

        current_stage = "S3"
        helper_reference, post_helper_capture = add_body_helper_reference_state(
            fixture, new_after_sources)
        root_reference, post_three_roots_capture = apply_literal_root_state(fixture)
        product_access = safe_read(PACKAGE / "fixture-product-access.sql", max_bytes=2 * 1024 * 1024)
        reference_access = fixture.apply_script(DATABASES["referenceNew"], product_access,
                                                "fixture-product-access-reference-new")
        reference_old_capture = baseline[DATABASES["referenceOld"]]
        pre_channel_access_capture = fixture.capture_catalog(
            DATABASES["referenceNew"], "s3-reference-new-pre-channel-access")
        channel_reference, post_channel_capture = apply_literal_channel_state(fixture)
        phase_captures = {
            "activeBaseline": reference_old_capture,
            "postSourcePreSeal": new_after_sources,
            "postHelperSeal": post_helper_capture,
            "postThreeRoots": post_three_roots_capture,
            "preChannelAccess": pre_channel_access_capture,
            "postChannel": post_channel_capture,
        }
        pin_evidence = build_pin_copies(fixture, phase_captures)
        stage_details["S3"] = {
            "independentReferenceOld": DATABASES["referenceOld"],
            "independentReferenceNew": DATABASES["referenceNew"],
            "helperOwnerAndAclReference": helper_reference,
            "literalNewRootReference": root_reference,
            "literalNewChannelReference": channel_reference,
            "fixtureProductAccess": {
                "sha256": digest(product_access),
                "referenceCommand": reference_access["label"],
            },
            "referencePhaseCaptureSha256": {
                name: digest(raw) for name, raw in sorted(phase_captures.items())
            },
            "pinDerivation": pin_evidence,
            "originalPendingSourcesRemainNullAndUnmodified": True,
            "targetDidNotSupplyAnyPin": True,
        }
        stages["S3"] = "PASS"
        stage_evidence["S3"] = True

        current_stage = "S4"
        operator_evidence = run_operator_transitions(
            fixture, reference_old_capture, new_after_sources, post_helper_capture,
            post_three_roots_capture, pre_channel_access_capture)
        final_target = fixture.capture_catalog(DATABASES["target"], "s4-final-target")
        final_reference_new = fixture.capture_catalog(DATABASES["referenceNew"], "s4-final-reference-new")
        if not evidence.stable_catalog_equality(final_target, final_reference_new):
            raise Rejected("final target catalog differs from independent reference-new")
        stage_details["S4"] = {
            "operatorTransitions": operator_evidence,
            "finalTargetVsReferenceNew": "PASS",
            "rawCaptures": {
                "target": {"sha256": digest(final_target), "bytes": len(final_target)},
                "referenceNew": {"sha256": digest(final_reference_new), "bytes": len(final_reference_new)},
            },
            "functionDefinitionsAndHashesComparedExactly": True,
            "onlyInternalForeignKeyTriggerGeneratedIdentityWasStructurallyMapped": True,
        }
        stages["S4"] = "PASS"
        stage_evidence["S4"] = True

        current_stage = "S5"
        acl_subset = run_s5_role_and_acl_checks(fixture, reference_old_capture, operator_evidence)
        stage_details["S5"] = {
            "status": "PASS",
            "boundedEffectiveRoleAclSubset": acl_subset,
            "fullS5Qualified": acl_subset["fullS5Qualified"],
            "fullS5Missing": acl_subset["fullS5Missing"],
        }
        stages["S5"] = "PASS"
        stage_evidence["S5"] = True

        current_stage = "S6"
        stage_details["S6"] = run_s6_actual_handler_test(fixture)
        stages["S6"] = "PASS"
        stage_evidence["S6"] = True

        current_stage = "S7"
        stage_details["S7"] = run_s7_populated_runtime(fixture)
        stages["S7"] = "PASS"
        stage_evidence["S7"] = True

        after_preflight = run_workspace_preflight(lock, manifest)
        source_after = dict(manifest["sourceFiles"])
        if (after_preflight["sourceClosure"] != preflight["sourceClosure"]
                or after_preflight["toolchain"] != tool_hashes_before):
            raise Rejected("source or toolchain bytes changed during fixture run")
        tool_hashes_after = after_preflight["toolchain"]
    except BaseException as exc:
        if run_dir is not None:
            error = {"type": type(exc).__name__, "message": str(exc)[:2000]}
        else:
            error = {"type": type(exc).__name__, "message": str(exc)[:2000]}
        current_stage = locals().get("current_stage", "S0")
        if current_stage in stages and stages[current_stage] == "NOT_RUN":
            stages[current_stage] = "FAILED"
            stage_evidence[current_stage] = False
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if fixture is not None:
            try:
                signal.setitimer(signal.ITIMER_REAL, max(0.001, final_deadline - time.monotonic()))
                cleanup_evidence = fixture.cleanup()
                if fixture.marker is None and work.exists():
                    info = work.lstat()
                    if (stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                            and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid()
                            and not list(work.iterdir())):
                        os.rmdir(work)
                        cleanup_evidence["emptyUnmarkedWorkRootRemoved"] = True
                    else:
                        cleanup_evidence = {"completed": False, "status": "UNMARKED_WORK_RETAINED"}
                if work.exists():
                    cleanup_evidence = {**cleanup_evidence, "completed": False,
                                        "status": "WORK_RETAINED",
                                        "markedWorkRetained": fixture.marker is not None}
            except BaseException as cleanup_error:
                cleanup_evidence = {
                    "completed": False,
                    "status": "FAILED",
                    "type": type(cleanup_error).__name__,
                    "message": str(cleanup_error)[:1000],
                    "markedWorkRetained": fixture.work.exists(),
                }
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)

    if cleanup_evidence.get("completed") is not True and error is None:
        error = {"type": "CleanupFailed", "message": "private fixture cleanup did not complete"}

    if run_dir is None:
        if error:
            sys.stderr.write("Consumer v3 private qualification rejected: " + error["type"] + "\n")
        return 1
    try:
        _, evidence, _ = load_local_modules()
        evidence.validate_stage_statuses(stages, stage_evidence)
    except BaseException as report_error:
        if error is None:
            error = {"type": type(report_error).__name__, "message": str(report_error)[:1000]}

    captures = {} if fixture is None else {
        label: {"sha256": digest(raw), "bytes": len(raw)}
        for label, raw in sorted(fixture.captures.items())
    }
    tool_report = {}
    if preflight is not None:
        before = preflight["toolchain"]
        tool_report["before"] = {
            "closureSha256": _toolchain_fingerprint(before),
            "postgresRegularFiles": len(before["postgresFiles"]),
            "postgresSymlinks": len(before["postgresSymlinks"]),
            "postgresDependencies": len(before["postgresDependencies"]),
            "bunSha256": before["bunSha256"],
            "runtimeDependencyTreeSha256": before["runtimeDependencyTreeSha256"],
            "prismaCliSha256": before["prismaCliSha256"],
            "prismaSchemaEngineSha256": before["prismaSchemaEngineSha256"],
        }
    if "tool_hashes_after" in locals():
        tool_report["after"] = {
            "closureSha256": _toolchain_fingerprint(tool_hashes_after),
            "postgresRegularFiles": len(tool_hashes_after["postgresFiles"]),
            "postgresSymlinks": len(tool_hashes_after["postgresSymlinks"]),
            "postgresDependencies": len(tool_hashes_after["postgresDependencies"]),
            "bunSha256": tool_hashes_after["bunSha256"],
            "runtimeDependencyTreeSha256": tool_hashes_after["runtimeDependencyTreeSha256"],
            "prismaCliSha256": tool_hashes_after["prismaCliSha256"],
            "prismaSchemaEngineSha256": tool_hashes_after["prismaSchemaEngineSha256"],
        }
    report = {
        "schemaVersion": 1,
        "runId": run_id,
        "scope": "consumer-derivatives-v3-full-product-s0-s7",
        "status": ("PRIVATE_S0_S7_PASS_NOT_PRODUCTION_QUALIFIED"
                   if error is None and all(value == "PASS" for value in stages.values())
                   else "SUBSET_RUN_NOT_QUALIFIED" if error is None else "FAILED"),
        "qualification": "NOT_QUALIFIED",
        "productionQualified": False,
        "deploymentAuthorized": False,
        "controllerSha256": locals().get("controller_sha", None),
        "bundleManifestSha256": locals().get("manifest_sha", None),
        "sourceHashesBefore": {} if preflight is None else dict(manifest["sourceFiles"]),
        "sourceHashesAfter": source_after,
        "toolHashes": tool_report,
        "stages": stages,
        "stageEvidence": stage_details,
        "actualCapturedEvidence": captures,
        "commands": [] if fixture is None else fixture.runner.records,
        "filledOperatorEvidence": {} if fixture is None else fixture.filled_operators,
        "cleanup": cleanup_evidence,
        "fullQualificationGaps": ([
            "S5 owner/ACL/operator denial checks did not complete",
        ] if stages["S5"] != "PASS" else []) + ([
            "S7 populated query-plan, cascade/revoke lookup and unrelated-row growth checks did not complete",
        ] if stages["S7"] != "PASS" else []) + [
            "Consumer handler fixture does not establish real relay, browser/mobile/desktop product or host service acceptance",
            "synthetic private fixture does not qualify the production Prisma migration ledger",
        ],
        "elapsedSeconds": round(time.monotonic() - started, 3),
        "failure": error,
    }
    try:
        write_new(run_dir / "run-report.json", _json_bytes(report))
        sys.stdout.write(str(run_dir / "run-report.json") + "\n")
    except BaseException as write_error:
        sys.stderr.write("Consumer v3 report write failed: " + type(write_error).__name__ + "\n")
        return 1
    return 0 if error is None and cleanup_evidence.get("completed") is True \
        and all(stages[f"S{i}"] == "PASS" for i in range(8)) else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="run the admitted private Consumer v3 fixture")
    parser.add_argument("--run", action="store_true", help="execute only after exact separate receipts validate")
    args = parser.parse_args(argv)
    if not args.run:
        parser.exit(2, "PREPARED_NOT_ADMITTED: --run requires independent-review.json and root-admission.json\n")
    os.umask(0o077)
    return run_qualification()


if __name__ == "__main__":
    raise SystemExit(main())






