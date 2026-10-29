"""Create an allowlisted source bundle only; never launch qualification work."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[2]
LOCK_PATH = HERE / "inputs.lock.json"
PLAN_PATH = HERE / "plan.json"
OUTPUT = WORKSPACE / "lomi-remote/artifacts/consumer-derivatives-v3-qualification-prep/source-bundle-final"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_json(data, label):
    try:
        return json.loads(data)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON input: " + label) from exc


def verify_allowlist(root, allowlist):
    """Read only named regular files and reject path escapes or source drift."""
    root = Path(root).resolve()
    contents = {}
    for relative, expected in sorted(allowlist.items()):
        rel = Path(relative)
        if rel.is_absolute() or ".." in rel.parts or not rel.parts:
            raise ValueError("unsafe allowlist path: " + relative)
        path = root
        for part in rel.parts:
            path = path / part
            if path.is_symlink():
                raise ValueError("allowlisted input traverses a symlink: " + relative)
            try:
                resolved = path.resolve(strict=True)
            except FileNotFoundError as exc:
                raise ValueError("allowlisted input is missing: " + relative) from exc
            if not resolved.is_relative_to(root):
                raise ValueError("allowlisted input escapes root: " + relative)
        if not path.is_file():
            raise ValueError("allowlisted input is not a regular file: " + relative)
        data = path.read_bytes()
        if sha256(data) != expected:
            raise ValueError("allowlisted input drift: " + relative)
        contents[relative] = data
    return contents


EXPECTED_INVOCATION_COUNTS = {
    "postgresInvocations": 0,
    "sqlInvocations": 0,
    "databaseConnections": 0,
    "bunInvocations": 0,
    "cargoInvocations": 0,
    "httpInvocations": 0,
    "networkInvocations": 0,
    "toolVersionQueries": 0,
    "candidateBuildInvocations": 0,
    "sealingOperatorInvocations": 0,
    "clientGenerationInvocations": 0,
}


def validate_plan(plan):
    if plan.get("status") != "PREPARED_NOT_EXECUTED":
        raise ValueError("plan status must remain PREPARED_NOT_EXECUTED")
    if plan.get("admission") is not None:
        raise ValueError("plan must not record admission")
    if plan.get("qualification") != "NOT_RUN":
        raise ValueError("qualification must remain NOT_RUN")
    if plan.get("postgresTarget") != "18.6":
        raise ValueError("plan target must remain PostgreSQL 18.6")
    if plan.get("sourceOnlyProhibition") != EXPECTED_INVOCATION_COUNTS:
        raise ValueError("plan invocation counters must remain exactly zero")
    stages = plan.get("stages")
    if not isinstance(stages, list) or [stage.get("id") for stage in stages] != ["S0", "S1", "S2", "S3", "S4", "S5"]:
        raise ValueError("plan must contain exactly the S0-S5 stages")
    if any(stage.get("status") != "NOT_RUN" for stage in stages):
        raise ValueError("every S0-S5 stage must remain NOT_RUN")
    if plan.get("futureAppointment") != "Separate explicit bounded PostgreSQL 18.6 S0-S5 appointment required":
        raise ValueError("plan appointment requirement drift")


def validate_destination(destination):
    destination = Path(destination)
    if not destination.is_absolute():
        destination = Path.cwd() / destination
    if ".." in destination.parts:
        raise ValueError("bundle destination must not contain parent traversal")
    destination = Path(destination.anchor, *destination.parts[1:])
    cursor = Path(destination.anchor)
    for part in destination.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("bundle destination traverses a symlink")
    if destination.exists():
        raise ValueError("bundle destination already exists")
    resolved_parent = destination.parent.resolve(strict=True)
    if not resolved_parent.is_dir() or not resolved_parent.is_relative_to(Path(destination.anchor).resolve()):
        raise ValueError("bundle destination parent is invalid")
    return destination


def assert_null_pins(catalog, helper):
    if catalog.get("status") != "UNMEASURED_CATALOG_FAIL_CLOSED":
        raise ValueError("catalog contract is not fail-closed")
    if helper.get("status") != "UNMEASURED_CATALOG_FAIL_CLOSED":
        raise ValueError("helper seal contract is not fail-closed")
    pin_fields = ("old_catalog_sha256", "new_catalog_sha256", "old_acl", "new_acl")
    if any(item.get(field) is not None for item in catalog.get("roots", []) for field in pin_fields):
        raise ValueError("root catalog/ACL pins must remain NULL")
    if any(item.get("catalog_sha256") is not None or item.get("acl") is not None
           for item in catalog.get("prerequisites", [])):
        raise ValueError("prerequisite catalog/ACL pins must remain NULL")
    if any(item.get(field) is not None for item in helper.get("helpers", []) for field in pin_fields):
        raise ValueError("helper catalog/ACL pins must remain NULL")


def verify_candidate_closure(contents):
    prefix = "lomi-remote/staging/consumer-derivatives-v3-successor/"
    manifest = read_json(contents[prefix + "candidate-source-sha256.json"], "candidate source manifest")
    for name, digest in manifest.items():
        path = prefix + name
        if path not in contents or sha256(contents[path]) != digest:
            raise ValueError("candidate manifest drift: " + name)
    provenance = read_json(contents[prefix + "successor-provenance.json"], "successor provenance")
    if provenance.get("successorCandidateManifestSha256") != sha256(contents[prefix + "candidate-source-sha256.json"]):
        raise ValueError("successor provenance does not pin candidate manifest")


def load_inputs(plan_override=None):
    lock_bytes = LOCK_PATH.read_bytes()
    lock = read_json(lock_bytes, "inputs.lock.json")
    if lock.get("status") != "SOURCE_ONLY_PREPARATION_LOCK":
        raise ValueError("unexpected preparation lock status")
    if lock.get("preparationStatus") != "PREPARED_NOT_EXECUTED" or lock.get("admission") != "CLOSED_REQUIRES_SEPARATE_EXPLICIT_APPOINTMENT":
        raise ValueError("preparation lock must remain unadmitted")
    if lock.get("postgresTarget") != "18.6 (declared future target; not probed)":
        raise ValueError("preparation target must remain the declared unprobed PostgreSQL 18.6 target")
    counters = lock.get("sourceOnlyProhibition", {})
    if counters != EXPECTED_INVOCATION_COUNTS:
        raise ValueError("source-only invocation counters must remain zero")
    plan_bytes = PLAN_PATH.read_bytes() if plan_override is None else plan_override
    validate_plan(read_json(plan_bytes, "plan.json"))
    contents = verify_allowlist(WORKSPACE, lock.get("sourceAllowlist", {}))
    prefix = "lomi-remote/staging/consumer-derivatives-v3-successor/"
    catalog = read_json(contents[prefix + "catalog-contract.pending.json"], "catalog contract")
    helper = read_json(contents[prefix + "helper-seal.pending.json"], "helper contract")
    assert_null_pins(catalog, helper)
    verify_candidate_closure(contents)
    return lock, lock_bytes, contents


def make_bundle_manifest(lock_bytes, plan_bytes, contents):
    return {
        "status": "PREPARED_NOT_EXECUTED",
        "admission": None,
        "qualification": "NOT_RUN",
        "inputsLockSha256": sha256(lock_bytes),
        "planSha256": sha256(plan_bytes),
        "sourceFiles": {name: sha256(data) for name, data in sorted(contents.items())},
    }


def expected_bundle_files(contents):
    return {"inputs.lock.json", "plan.json", "bundle-manifest.json"} | {"source/" + name for name in contents}


def validate_bundle(bundle, lock, lock_bytes, contents):
    bundle = Path(bundle)
    plan_bytes = PLAN_PATH.read_bytes()
    bundled_plan_bytes = (bundle / "plan.json").read_bytes()
    validate_plan(read_json(bundled_plan_bytes, "bundled plan"))
    expected_manifest = make_bundle_manifest(lock_bytes, plan_bytes, contents)
    expected = expected_bundle_files(contents)
    found = set()
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise ValueError("bundle must not contain symlinks")
        if path.is_file():
            found.add(path.relative_to(bundle).as_posix())
    if found != expected:
        raise ValueError("bundle file set differs from allowlist")
    if (bundle / "inputs.lock.json").read_bytes() != lock_bytes:
        raise ValueError("bundle input lock drift")
    if (bundle / "plan.json").read_bytes() != plan_bytes:
        raise ValueError("bundle plan drift")
    if read_json((bundle / "bundle-manifest.json").read_bytes(), "bundle manifest") != expected_manifest:
        raise ValueError("bundle manifest drift")
    for name, expected_hash in expected_manifest["sourceFiles"].items():
        data = (bundle / "source" / name).read_bytes()
        if sha256(data) != expected_hash:
            raise ValueError("bundle source drift: " + name)
    return expected_manifest


def create_bundle(destination=OUTPUT):
    lock, lock_bytes, contents = load_inputs()
    destination = validate_destination(destination)
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in contents.items():
        target = destination / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    plan_bytes = PLAN_PATH.read_bytes()
    manifest = make_bundle_manifest(lock_bytes, plan_bytes, contents)
    (destination / "inputs.lock.json").write_bytes(lock_bytes)
    (destination / "plan.json").write_bytes(plan_bytes)
    (destination / "bundle-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    validate_bundle(destination, lock, lock_bytes, contents)
    return destination


if __name__ == "__main__":
    print(create_bundle())
