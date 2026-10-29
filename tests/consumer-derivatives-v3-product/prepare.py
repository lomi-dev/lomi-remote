"""Pure source freezing for the private Consumer v3 product appointment."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import re
import stat
import uuid

HERE = Path(__file__).resolve().parent
WORKSPACE = Path("/Users/woro/Documents/Lomi")
PROJECT = WORKSPACE / "lomi-remote"
LOCK_PATH = HERE / "inputs.lock.json"
PLAN_PATH = HERE / "plan.json"
ARTIFACTS = PROJECT / "artifacts"
LOCAL_FILES = (
    "admission.py",
    "capture.sql",
    "controller.py",
    "evidence.py",
    "prepare.py",
    "test_controller.py",
    "helper_denials.py",
    "test_helper_denials.py",
    "owner_state_denials.py",
    "test_owner_state_denials.py",
    "s7_plans.py",
    "test_s7_plans.py",
    "s7_spec.py",
    "test_s7_spec.py",
    "s7_evidence.py",
    "test_s7_evidence.py",
)
OUTPUT_PREFIX = "consumer-derivatives-v3-product-"
BUN_PATH = "/tmp/bun-v1.4.2/bun-darwin-aarch64/bun"
BUN_CANONICAL_PATH = "/private/tmp/bun-v1.4.2/bun-darwin-aarch64/bun"
BUN_SHA256 = "35d20dd0263e5c950194434b925454fdfa9ba6e4467da960410fa05b08a7a5b5"
PRISMA_CLI_PATH = str(WORKSPACE / "auth-app/node_modules/prisma/build/index.js")
PRISMA_CLI_SHA256 = "763611d694b08952ced7c5abb3b9d61906fed0a8997d9214ac918a43928e0fc8"
PRISMA_SCHEMA_ENGINE_PATH = str(WORKSPACE / "auth-app/node_modules/@prisma/engines/schema-engine-darwin-arm64")
PRISMA_SCHEMA_ENGINE_SHA256 = "ee46310d1c0edb2b55eed39264828c3f35c5334d3a19930b44fb1dba56cdba7e"


class Rejected(ValueError):
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

S7_PURPOSE = (
    "Build unrelated issued principal rows through actual production flow "
    "primitives at T=1000 and T=10000: T remote-web plus T mobile rows (2T "
    "total) at each target, using the existing four private role pools. Require "
    "at least T in each kind-specific remote_web_session and mobile_session "
    "relation, and 2T in each shared consumer_approval_intent, "
    "consumer_derivative_consent, and remote_service_authorization relation. "
    "Add eight dedicated fixtures (two live pending plus six controls/tombstones) "
    "outside those unrelated populations. Require seven leading cascade lookup "
    "plans and three pending principal absence plans at both target sizes, five "
    "actual rollback DELETE/RI-trigger measurements at each target (ten total), "
    "two source-TTL deletion measurements retaining proof/consent/C and canonical "
    "liveness, real logout "
    "tombstones, unrelated controls, exact private receipt and raw-plan "
    "validation, and verified cleanup. This private stage does not qualify a "
    "real relay or physical phone/mobile/desktop clients."
)

PLAN_STAGE_PURPOSES = [
    "Verify exact source closure, Homebrew PostgreSQL 18.6 and Bun dependency hashes/versions after two distinct source-bound receipts; establish marked private work and original deadline.",
    "Run pinned Prisma 7.10 migrate deploy against each private database, verify every private ledger row/checksum against pinned migration bytes, apply active operations, then compare exact old-source captures. This private fixture ledger is not production migration-history qualification.",
    "Install literal Consumer v3 sources in the target and source-derived new reference in reviewed order.",
    "Measure old/new root, helper, typed wrapper and product-channel catalogs from independent references; fill NULL spans only in private operator copies.",
    "Run helper seal, three-root and product-channel operators through all-old/all-new idempotency, mixed-state and drift-denial checks. Helper and root operators must reject real authentication-bypassing pg_proc body changes by exact P0001 guard reason and restore the complete catalog before positive controls. Run each owner-state subset at its measured phase; compare final target to reference-new.",
    "Measure effective role ACL positives/denials, exact host preservation and nine reviewed Exchange parent column grants. Require eighty sealed-helper denials as actual nonoperator logins, plus all twenty-eight owner-state rejection attempts executed at each operator's exact S4 phase after genuine positive controls; bound transcripts and complete catalog/role rollback must validate before PASS.",
    "Run pinned actual issuance/lifecycle/inventory/ACL and signed Host/Pairing/Channel/Ticket handler transactions with four explicit private URLs and four max-2 pools. Require both derivative kinds, fifteen typed overloads, owned heartbeat drain, exact operation recovery after lost ACK, uncertain ticket outcome without replay, and direct retained-key cleanup proof.",
    S7_PURPOSE,
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


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(raw, label):
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
        raise Rejected("invalid JSON: " + label) from error


def safe_relative(value):
    if type(value) is not str or not value or "\\" in value:
        raise Rejected("invalid relative input path")
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise Rejected("unsafe relative input path")
    return path


def read_exact(root, relative, expected_sha256):
    root = Path(root)
    rel = safe_relative(relative)
    if type(expected_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise Rejected("invalid source digest")
    current = root
    for part in rel.parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise Rejected("source missing: " + relative) from error
        if stat.S_ISLNK(info.st_mode):
            raise Rejected("source traverses symlink: " + relative)
    if not current.is_file():
        raise Rejected("source is not a regular file: " + relative)
    raw = current.read_bytes()
    if sha256(raw) != expected_sha256:
        raise Rejected("source hash drift: " + relative)
    return raw


def load_lock(lock_override=None):
    raw = LOCK_PATH.read_bytes() if lock_override is None else lock_override
    lock = strict_json(raw, "inputs.lock.json")
    if lock.get("schemaVersion") != 1 or lock.get("status") != "SOURCE_LOCKED_NOT_ADMITTED":
        raise Rejected("source lock status")
    if lock.get("postgresVersion") != "18.6" or lock.get("bunVersion") != "1.4.2":
        raise Rejected("tool versions must remain exact")
    if lock.get("admission") != "TWO_DISTINCT_SOURCE_BOUND_INTEGRATOR_AND_REVIEWER_RECEIPTS_REQUIRED":
        raise Rejected("source lock admission state")
    if lock.get("productionQualified") is not False:
        raise Rejected("production qualification must remain false")
    sources = lock.get("sourceAllowlist")
    if type(sources) is not dict or not sources:
        raise Rejected("source allowlist required")
    for name, pin in sources.items():
        safe_relative(name)
        if type(pin) is not str or not re.fullmatch(r"[0-9a-f]{64}", pin):
            raise Rejected("invalid source allowlist digest")
    successor_manifest = "lomi-remote/staging/consumer-derivatives-v3-product-successor/source-manifest.json"
    if (successor_manifest not in sources
            or lock.get("successorManifestSha256") != sources[successor_manifest]):
        raise Rejected("successor manifest pin differs from the exact source allowlist")
    trees = lock.get("closedTrees")
    if type(trees) is not dict or not trees:
        raise Rejected("closed source trees required")
    for root, names in trees.items():
        safe_relative(root)
        if type(names) is not list or not names or len(names) != len(set(names)):
            raise Rejected("invalid closed source tree")
        for name in names:
            rel = safe_relative(name)
            if not str(rel).startswith(root.rstrip("/") + "/"):
                raise Rejected("closed-tree file outside root")
            if name not in sources:
                raise Rejected("closed-tree file absent from source allowlist")
    postgres_files = lock.get("postgresFiles")
    postgres_links = lock.get("postgresSymlinks")
    postgres_deps = lock.get("postgresDependencies")
    bun_deps = lock.get("bunDependencies")
    if (lock.get("postgresRoot") != "/opt/homebrew/Cellar/postgresql@18/18.6_1"
            or lock.get("postgresVersion") != "18.6"
            or type(postgres_files) is not dict or len(postgres_files) < 3000
            or type(postgres_links) is not dict or type(postgres_deps) is not dict or not postgres_deps
            or type(lock.get("postgresDependencyAliases")) is not dict
            or type(lock.get("postgresDependencyAliasTargets")) is not dict
            or type(lock.get("postgresFormulaAliases")) is not dict
            or type(lock.get("systemDependencies")) is not dict or not lock["systemDependencies"]
            or type(lock.get("hostPlatform")) is not dict
            or type(lock.get("postgresLoadCommands")) is not dict or not lock["postgresLoadCommands"]
            or type(lock.get("bunLoadCommands")) is not dict or not lock["bunLoadCommands"]
            or any(type(lock.get(field + "Sha256")) is not str
                   or not re.fullmatch(r"[0-9a-f]{64}", lock[field + "Sha256"])
                   for field in ("postgresLoadCommands", "bunLoadCommands"))
            or type(lock.get("bunPath")) is not str or not Path(lock["bunPath"]).is_absolute()
            or type(lock.get("bunCanonicalPath")) is not str or not Path(lock["bunCanonicalPath"]).is_absolute()
            or type(lock.get("bunSha256")) is not str or not re.fullmatch(r"[0-9a-f]{64}", lock["bunSha256"])
            or lock.get("bunPath") != BUN_PATH
            or lock.get("bunCanonicalPath") != BUN_CANONICAL_PATH
            or lock.get("bunSha256") != BUN_SHA256
            or type(bun_deps) is not dict
            or type(lock.get("bunDependencyAliases")) is not dict
            or type(lock.get("bunDependencyAliasTargets")) is not dict
            or lock.get("runtimeDependencyPath") != str(WORKSPACE / "auth-app/node_modules")
            or type(lock.get("runtimeDependencySymlinks")) is not dict
            or type(lock.get("runtimeDependencyTreeSha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", lock["runtimeDependencyTreeSha256"])
            or lock.get("prismaCliPath") != PRISMA_CLI_PATH
            or lock.get("prismaCliSha256") != PRISMA_CLI_SHA256
            or lock.get("prismaSchemaEnginePath") != PRISMA_SCHEMA_ENGINE_PATH
            or lock.get("prismaSchemaEngineSha256") != PRISMA_SCHEMA_ENGINE_SHA256):
        raise Rejected("exact Homebrew PG18.6, Bun and Auth dependency closure required")
    required_pg = {"bin/initdb", "bin/postgres", "bin/pg_ctl", "bin/psql"}
    if not required_pg <= set(postgres_files):
        raise Rejected("required PostgreSQL executables are outside source lock")
    return lock, raw


def verify_allowlist(root, lock):
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root:
        raise Rejected("canonical source root required")
    contents = {}
    for relative, expected in sorted(lock["sourceAllowlist"].items()):
        contents[relative] = read_exact(root, relative, expected)
    for tree_root, names in lock["closedTrees"].items():
        directory = root / safe_relative(tree_root)
        if directory.is_symlink() or not directory.is_dir():
            raise Rejected("closed source directory invalid: " + tree_root)
        found = set()
        for item in directory.rglob("*"):
            if item.is_symlink():
                raise Rejected("closed source tree contains symlink: " + tree_root)
            if item.is_file():
                found.add(item.relative_to(root).as_posix())
        if found != set(names):
            raise Rejected("closed source file set drift: " + tree_root)
    return contents


def validate_destination(destination):
    destination = Path(destination)
    if not destination.is_absolute() or destination.parent != ARTIFACTS:
        raise Rejected("bundle must be a direct artifact child")
    if not re.fullmatch(re.escape(OUTPUT_PREFIX) + r"[0-9a-f-]{36}", destination.name):
        raise Rejected("bundle directory name must contain a UUID")
    parsed = uuid.UUID(destination.name[len(OUTPUT_PREFIX):])
    if str(parsed) != destination.name[len(OUTPUT_PREFIX):]:
        raise Rejected("bundle UUID must be canonical")
    for path in (destination, destination.parent, *destination.parent.parents):
        if path.is_symlink():
            raise Rejected("bundle ancestry contains symlink")
    if destination.exists():
        raise Rejected("bundle destination already exists")
    if not ARTIFACTS.is_dir():
        raise Rejected("artifacts directory is unavailable")
    return destination


def make_manifest(lock_raw, contents, plan_raw):
    lock = strict_json(lock_raw, "inputs.lock.json")
    return {
        "schemaVersion": 1,
        "status": "PREPARED_NOT_ADMITTED",
        "admission": None,
        "productionQualified": False,
        "qualification": "NOT_RUN",
        "stages": {f"S{number}": "NOT_RUN" for number in range(8)},
        "inputsLockSha256": sha256(lock_raw),
        "planSha256": sha256(plan_raw),
        "controllerSha256": sha256(contents["controller.py"]),
        "captureSha256": sha256(contents["capture.sql"]),
        "evidenceModuleSha256": sha256(contents["evidence.py"]),
        "sourceFiles": {name: sha256(raw) for name, raw in sorted(contents.items())},
        "postgresVersion": lock["postgresVersion"],
        "postgresRoot": lock["postgresRoot"],
        "postgresAliasPath": lock["postgresAliasPath"],
        "postgresAliasTarget": lock["postgresAliasTarget"],
        "postgresFiles": lock["postgresFiles"],
        "postgresSymlinks": lock["postgresSymlinks"],
        "postgresDependencies": lock["postgresDependencies"],
        "postgresDependencyAliases": lock["postgresDependencyAliases"],
        "postgresFormulaAliases": lock["postgresFormulaAliases"],
        "hostPlatform": lock["hostPlatform"],
        "systemDependencies": lock["systemDependencies"],
        "postgresLoadCommands": lock["postgresLoadCommands"],
        "postgresLoadCommandsSha256": lock["postgresLoadCommandsSha256"],
        "bunLoadCommands": lock["bunLoadCommands"],
        "bunLoadCommandsSha256": lock["bunLoadCommandsSha256"],
        "bunVersion": lock["bunVersion"],
        "bunPath": lock["bunPath"],
        "bunCanonicalPath": lock["bunCanonicalPath"],
        "bunSha256": lock["bunSha256"],
        "bunDependencies": lock["bunDependencies"],
        "runtimeDependencyPath": lock["runtimeDependencyPath"],
        "runtimeDependencySymlinks": lock["runtimeDependencySymlinks"],
        "dependencyVersions": lock["dependencyVersions"],
        "runtimeDependencyTreeSha256": lock["runtimeDependencyTreeSha256"],
        "prismaCliPath": lock["prismaCliPath"],
        "prismaCliSha256": lock["prismaCliSha256"],
        "prismaSchemaEnginePath": lock["prismaSchemaEnginePath"],
        "prismaSchemaEngineSha256": lock["prismaSchemaEngineSha256"],
    }


def _mkdir_private(path):
    os.mkdir(path, 0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.getuid()):
        raise Rejected("private bundle directory identity")


def _write_new(path, raw, mode=0o600):
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


def validate_bundle(bundle, lock_raw=None, contents=None):
    bundle = Path(bundle)
    if bundle.is_symlink() or not bundle.is_dir():
        raise Rejected("prepared bundle must be a directory")
    info = bundle.lstat()
    if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise Rejected("prepared bundle directory metadata")
    lock_raw = (bundle / "inputs.lock.json").read_bytes() if lock_raw is None else lock_raw
    lock = strict_json(lock_raw, "bundled lock")
    manifest_raw = (bundle / "bundle-manifest.json").read_bytes()
    manifest = strict_json(manifest_raw, "bundle manifest")
    plan_raw = (bundle / "plan.json").read_bytes()
    plan = strict_json(plan_raw, "plan")
    validate_plan(plan)
    expected_names = set(LOCAL_FILES) | {"bundle-manifest.json", "inputs.lock.json", "plan.json"}
    expected_names |= {"inputs/" + name for name in lock["sourceAllowlist"]}
    found = set()
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise Rejected("prepared bundle contains symlink")
        if path.is_file():
            found.add(path.relative_to(bundle).as_posix())
    optional_receipts = {
        "admission/independent-review.json",
        "admission/root-admission.json",
    }
    if not expected_names <= found or found - expected_names - optional_receipts:
        raise Rejected("prepared bundle file set differs from manifest")
    if contents is None:
        contents = verify_allowlist(WORKSPACE, lock)
        for name in LOCAL_FILES:
            local = bundle / name
            if local.is_symlink() or not local.is_file():
                raise Rejected("prepared local source unavailable: " + name)
            contents[name] = local.read_bytes()
    for name, pin in lock["sourceAllowlist"].items():
        raw = (bundle / "inputs" / safe_relative(name)).read_bytes()
        if sha256(raw) != pin or raw != contents[name]:
            raise Rejected("prepared source drift: " + name)
    expected_manifest = make_manifest(lock_raw, contents, plan_raw)
    if manifest != expected_manifest:
        raise Rejected("prepared bundle manifest drift")
    return manifest


def validate_plan(plan):
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
        raise Rejected("plan does not match the closed v2 unadmitted contract")


def create_bundle():
    lock, lock_raw = load_lock()
    contents = verify_allowlist(WORKSPACE, lock)
    for name in LOCAL_FILES:
        path = HERE / name
        if path.is_symlink() or not path.is_file():
            raise Rejected("local controller source unavailable: " + name)
        contents[name] = path.read_bytes()
    spec = importlib.util.spec_from_file_location(
        "consumer_v3_prepare_toolchain_check", HERE / "controller.py")
    if spec is None or spec.loader is None:
        raise Rejected("controller toolchain verifier unavailable")
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    # During preparation the controller module lives beside its sources and
    # has no `inputs/auth-app` subtree yet. Use the already-hash-checked
    # workspace package for the pure dependency-version check; an admitted
    # bundle resolves this same constant path inside its copied inputs.
    controller.AUTH = WORKSPACE / "auth-app"
    controller.verify_toolchain(lock)
    plan_raw = PLAN_PATH.read_bytes()
    validate_plan(strict_json(plan_raw, "plan.json"))
    destination = validate_destination(ARTIFACTS / (OUTPUT_PREFIX + str(uuid.uuid4())))
    _mkdir_private(destination)
    for name in LOCAL_FILES:
        _write_new(destination / name, contents[name])
    _write_new(destination / "inputs.lock.json", lock_raw)
    _write_new(destination / "plan.json", plan_raw)
    for name, raw in lock["sourceAllowlist"].items():
        target = destination / "inputs" / safe_relative(name)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.parent.is_symlink():
            raise Rejected("prepared source destination symlink")
        _write_new(target, contents[name])
    manifest = make_manifest(lock_raw, contents, plan_raw)
    manifest_raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    _write_new(destination / "bundle-manifest.json", manifest_raw)
    validate_bundle(destination, lock_raw, contents)
    return destination


if __name__ == "__main__":
    print(create_bundle())
