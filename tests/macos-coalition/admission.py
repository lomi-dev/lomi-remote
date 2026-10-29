"""Bounded LaunchOnlyOnce observations, never a closed-admission theorem."""
import hashlib
import json
import os
from pathlib import Path
import re
import time


def allowed_extra(name):
    return bool(re.fullmatch(r"(?:start-[0-9a-f]{32}\.json|invocation-[0-9a-f]{32}\.lock|sample\.(?:live|repeat)\.request|sample\.(?:live|repeat|final)\.json)", name))


def records(api, profile):
    descriptor = api["directory"](Path(profile))
    try:
        names = os.listdir(descriptor)
        starts = [name for name in names if name.startswith("start-")]
        if len(starts) > 16:
            raise RuntimeError("invocation_record_limit")
        result = []
        for name in sorted(starts):
            if not allowed_extra(name):
                raise RuntimeError("invalid_invocation_record_name")
            value = json.loads(api["read_private"](descriptor, name))
            nonce = name.removeprefix("start-").removesuffix(".json")
            if value.get("schema") != 1 or value.get("nonce") != nonce or type(value.get("pid")) is not int or value["pid"] <= 0 or value.get("auditPid") != value["pid"] or value.get("auditEuid") != os.geteuid() or type(value.get("auditPidversion")) is not int or value["auditPidversion"] <= 0:
                raise RuntimeError("invalid_invocation_identity")
            if not isinstance(value.get("auditToken"), list) or len(value["auditToken"]) != 8 or any(type(word) is not int or not 0 <= word <= 0xffffffff for word in value["auditToken"]):
                raise RuntimeError("invalid_audit_token_shape")
            sample = value["self"]
            if sample["outcome"] != "Observed" or sample["pid"] != value["pid"] or sample["bytes"] != 40 or any(type(sample[key]) is not int or sample[key] <= 0 for key in ("resource", "jetsam")):
                raise RuntimeError("invocation_query_unknown")
            if "invocation-" + nonce + ".lock" not in names:
                raise RuntimeError("invocation_lifetime_missing")
            result.append(value)
        return result
    finally:
        os.close(descriptor)


def capture_proofs(api, profile):
    descriptor = api["directory"](Path(profile))
    try:
        names = set(os.listdir(descriptor)) - {"result.json", "controller.lock"}
        if any(not allowed_extra(name) for name in names):
            raise RuntimeError("unknown_profile_entries")
        values = records(api, profile)
        expected_locks = {"invocation-" + value["nonce"] + ".lock" for value in values}
        if {name for name in names if name.endswith(".lock")} != expected_locks:
            raise RuntimeError("orphan_invocation_lifetime")
        proofs = {}
        for name in sorted(names):
            content = api["read_private"](descriptor, name)
            if name.endswith(".lock"):
                fd = api["wait_lifetime"](profile, name=name)
                try:
                    metadata = os.fstat(fd)
                    proofs[name] = {"sha256": hashlib.sha256(content).hexdigest(), "device": metadata.st_dev, "inode": metadata.st_ino}
                finally:
                    os.close(fd)
            else:
                proofs[name] = {"sha256": hashlib.sha256(content).hexdigest()}
        if set(os.listdir(descriptor)) != names | {"result.json", "controller.lock"}:
            raise RuntimeError("invocation_set_changed")
        return proofs
    finally:
        os.close(descriptor)


def validate_matrix(result, parent_coalitions):
    initial_pairs = []
    for suffix, expected_counts in (("a", [1, 1, 1, 1, 2]), ("b", [1, 1, 1, 2, 3])):
        value = result["jobs"][suffix]
        phases = value["phases"]
        if [len(phases[key]) for key in ("initial", "live", "repeat", "postExit", "rebootstrap")] != expected_counts:
            return False
        previous = set()
        for phase in ("initial", "live", "repeat", "postExit", "rebootstrap"):
            nonces = {record["nonce"] for record in phases[phase]}
            if len(nonces) != len(phases[phase]) or not previous.issubset(nonces):
                return False
            previous = nonces
        original = phases["initial"][0]
        pair = (original["self"]["resource"], original["self"]["jetsam"])
        if any(number <= 0 for number in pair) or any(pair[index] == parent_coalitions[index] for index in (0, 1)):
            return False
        initial_pairs.append(pair)
        counts = []
        for sample in value["samples"].values():
            if sample["self"] != original["self"]:
                return False
            usage = sample["usage"]
            if usage["outcome"] != "Observed" or any(type(usage[key]) is not int for key in ("started", "exited", "active")) or usage["active"] != 1 or usage["started"] - usage["exited"] != 1 or usage["exited"] < 0:
                return False
            counts.append((usage["started"], usage["exited"]))
        if len(counts) != 3 or len(set(counts)) != 1:
            return False
        post = {record["nonce"]: record for record in phases["postExit"]}
        fresh = [record for record in phases["rebootstrap"] if record["nonce"] not in post]
        if len(fresh) != 1 or any(fresh[0]["self"][key] == original["self"][key] for key in ("resource", "jetsam")):
            return False
        if suffix == "b" and any(any(record["self"][key] != original["self"][key] for key in ("resource", "jetsam")) for record in post.values()):
            return False
    return all(initial_pairs[0][index] != initial_pairs[1][index] for index in (0, 1))


def run(api):
    report, root, binary = api["report"], api["root"], api["binary"]
    for domain_name in ("gui-aqua", "user-background"):
        result = {"outcome": "Unknown", "closedAdmissionQualified": False, "jobs": {}}
        report["domains"][domain_name] = result
        group = []
        try:
            for suffix in ("a", "b"):
                job, content = api["fixed_job"](root, binary, domain_name, suffix, "admission")
                profile = Path(job["profile"])
                profile.mkdir(mode=0o700)
                api["sync_directory"](profile.parent)
                job["cleanupConfirmed"] = False
                report["jobs"].append(job)
                group.append(job)
                api["expected"][job["label"]] = content
                job["overrideBefore"] = api["overrides"](job["domain"], job["label"])
                if job["overrideBefore"] is not None or api["observe"](job) is not None or api["read_private"](api["agent_fd"], job["fileName"]) is not None:
                    raise RuntimeError("fresh_owned_registration_required")
                job["before"] = {"job": "absent", "plist": "absent", "profile": "new-empty", "override": None}
                job["registrationIntent"] = True
                job["plistSha256"] = hashlib.sha256(content).hexdigest()
                api["save"]()
                api["publish"](api["agent_fd"], job["fileName"], content)
                job["bootstrapIntent"] = True
                api["save"]()
                if api["command"]("admission-bootstrap", ["/bin/launchctl", "bootstrap", job["domain"], job["plist"]], manager=True).returncode:
                    raise RuntimeError("admission_bootstrap_failed")
                job["kickstartIntent"] = True
                api["save"]()
                if api["command"]("admission-initial-demand", ["/bin/launchctl", "kickstart", job["target"]], manager=True).returncode:
                    raise RuntimeError("admission_initial_start_failed")
                deadline = time.monotonic() + 2
                while True:
                    value = api["state_value"](job)
                    if value is not None:
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError("admission_result_timeout")
                    time.sleep(0.005)
                if value.get("schema") != "admission-v1" or value.get("cleanupConfirmed") is not True or value.get("nonforking") is not True or value.get("numericSignalsUsed") is not False:
                    raise RuntimeError("admission_schema_unknown")
                live = api["observe"](job)
                if not live or live["pid"] != value["self"]["pid"]:
                    raise RuntimeError("admission_manager_identity_mismatch")
                job["observation"] = value
                phases = {"initial": records(api, profile)}
                for phase in ("live", "repeat"):
                    if phase == "repeat":
                        job["repeatDemandIntent"] = True
                        api["save"]()
                        for _ in range(3):
                            api["command"]("admission-live-repeat-demand", ["/bin/launchctl", "kickstart", job["target"]], manager=True)
                    descriptor = api["directory"](profile)
                    try:
                        api["publish"](descriptor, "sample." + phase + ".request", b"")
                    finally:
                        os.close(descriptor)
                    deadline = time.monotonic() + 1
                    while not (profile / ("sample." + phase + ".json")).exists():
                        if time.monotonic() >= deadline:
                            raise RuntimeError("admission_sample_timeout")
                        time.sleep(0.005)
                    phases[phase] = records(api, profile)
                fd = api["wait_lifetime"](profile)
                os.close(fd)
                job["postExitDemandIntent"] = True
                api["save"]()
                api["command"]("admission-post-exit-demand", ["/bin/launchctl", "kickstart", job["target"]], manager=True)
                time.sleep(1.5)
                phases["postExit"] = records(api, profile)
                job["rebootstrapIntent"] = True
                api["save"]()
                api["command"]("admission-exact-bootout", ["/bin/launchctl", "bootout", job["target"]], manager=True)
                deadline = time.monotonic() + 5
                while api["observe"](job) is not None:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("admission_bootout_uncertain")
                    time.sleep(0.01)
                api["save"]()
                bootstrap = api["command"]("admission-exact-rebootstrap", ["/bin/launchctl", "bootstrap", job["domain"], job["plist"]], manager=True)
                if bootstrap.returncode == 0:
                    api["save"]()
                    api["command"]("admission-rebootstrap-demand", ["/bin/launchctl", "kickstart", job["target"]], manager=True)
                    time.sleep(1)
                phases["rebootstrap"] = records(api, profile)
                descriptor = api["directory"](profile)
                try:
                    samples = {phase: json.loads(api["read_private"](descriptor, "sample." + phase + ".json")) for phase in ("live", "repeat", "final")}
                finally:
                    os.close(descriptor)
                result["jobs"][suffix] = {"launchOnlyOnce": suffix == "a", "phases": phases, "samples": samples,
                                           "recordCounts": {phase: len(values) for phase, values in phases.items()},
                                           "rebootstrapExit": bootstrap.returncode}
                api["save"]()
            counts_a = result["jobs"]["a"]["recordCounts"]
            counts_b = result["jobs"]["b"]["recordCounts"]
            result["positiveControlRecordedSecondEntry"] = counts_b["postExit"] >= 2
            result["noAdditionalRecordedInvocationBeforeRebootstrap"] = counts_a["initial"] == counts_a["live"] == counts_a["repeat"] == counts_a["postExit"] == 1
            result["matrixMatches"] = validate_matrix(result, api["parent_coalitions"])
            result["outcome"] = "Observed" if result["matrixMatches"] else "Unknown"
        except Exception as error:
            result["failureType"] = type(error).__name__
            result["failureReason"] = str(error)
        finally:
            failures = api["cleanup_all"](group, api["cleanup_job"])
            if failures:
                report.setdefault("cleanupFailures", []).extend(failures)
                raise RuntimeError("admission_cleanup_uncertain")
            api["save"]()
    return all(value["outcome"] == "Observed" for value in report["domains"].values())
