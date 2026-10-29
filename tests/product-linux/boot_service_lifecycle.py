#!/usr/bin/env python3
"""Qualify and clean up one marked product systemd-user boot service."""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from owned_process import initialize_process_ownership, run_owned


def expected_unit(profile):
    """Mirror the product's deterministic FNV-1a unit name derivation."""
    value = 0x6c62272e07bb014262b821756295c58d
    for byte in str(profile).encode():
        value ^= byte
        value = (value * 0x1000000000000000000013b) & ((1 << 128) - 1)
    return "lomiremote-%032x.service" % value


def require_changed_boot_id(pre_boot_id, current_boot_id):
    pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    if (not isinstance(pre_boot_id, str) or re.fullmatch(pattern, pre_boot_id) is None
            or not isinstance(current_boot_id, str) or re.fullmatch(pattern, current_boot_id) is None
            or current_boot_id == pre_boot_id):
        raise RuntimeError("Cold boot identity is unchanged or invalid")


def normalize_journal_boot_id(value):
    """Normalize systemd's compact _BOOT_ID to procfs UUID form."""
    if not isinstance(value, str):
        return None
    if re.fullmatch(r"[0-9a-f]{32}", value, re.IGNORECASE):
        return value.lower()
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                    value, re.IGNORECASE):
        return value.replace("-", "").lower()
    return None


def absent_unit_confirmed(unit_file_present, wants_link_present, properties):
    """Accept absence only when files and all manager state prove it."""
    if unit_file_present or wants_link_present or not isinstance(properties, dict):
        return False
    required = {"LoadState", "ActiveState", "MainPID", "FragmentPath", "DropInPaths"}
    if not required.issubset(properties):
        return False
    return (properties["LoadState"] == "not-found"
            and properties["ActiveState"] in ("inactive", "failed")
            and properties["MainPID"] == "0"
            and properties["FragmentPath"] == ""
            and properties["DropInPaths"] == "")


def linger_mutation_command(action, uid):
    if action not in ("enable-linger", "disable-linger") or not isinstance(uid, int) or uid < 0:
        raise RuntimeError("Invalid bounded linger mutation")
    return ["/usr/bin/sudo", "-n", "/usr/bin/loginctl", action, str(uid)]


def registration_matches(registration, profile, executable, account, mode, unit):
    return (isinstance(registration, dict)
            and registration.get("profile") == str(profile)
            and registration.get("executable") == str(executable)
            and registration.get("account") == account
            and registration.get("mode") == mode
            and registration.get("unit") == unit)


def ssh_journal_command():
    return ["/usr/bin/sudo", "-n", "/usr/bin/journalctl", "--boot", "--no-pager",
            "--output=json", "_COMM=sshd"]


def qualify_timestamps(boot_id, unit_values, ssh_events, uid, account):
    """Require complete, same-boot monotonic evidence before first observed login."""
    normalized_boot_id = normalize_journal_boot_id(boot_id)
    if normalized_boot_id is None:
        raise RuntimeError("Invalid current boot identity")
    # Linux account names normally follow this restricted spelling. Validate
    # before building the journal-message matcher, then escape at the regex
    # boundary so the account can never contribute regular-expression syntax.
    if not isinstance(account, str) or re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", account) is None:
        raise RuntimeError("Invalid operating-system account name")
    accepted_login = re.compile(r"^Accepted \S+ for " + re.escape(account) + r"(?: |$)")
    required = ("user-runtime-dir@%s.service" % uid, "user@%s.service" % uid)
    timestamps = {}
    for unit in required:
        value = unit_values.get(unit)
        if not isinstance(value, str) or not value.isdecimal() or int(value) <= 0:
            raise RuntimeError("Missing or invalid monotonic timestamp: " + unit)
        timestamps[unit] = int(value)
    value = unit_values.get("product")
    if not isinstance(value, str) or not value.isdecimal() or int(value) <= 0:
        raise RuntimeError("Missing or invalid monotonic timestamp: product unit")
    timestamps["product"] = int(value)
    events = [event for event in ssh_events
              if normalize_journal_boot_id(event.get("_BOOT_ID")) == normalized_boot_id
              and isinstance(event.get("MESSAGE"), str)
              and accepted_login.match(event["MESSAGE"]) is not None]
    if not events:
        raise RuntimeError("No complete first observed SSH login evidence")
    values = [event.get("__MONOTONIC_TIMESTAMP") for event in events]
    if any(not isinstance(item, str) or not item.isdecimal() or int(item) <= 0 for item in values):
        raise RuntimeError("Truncated or invalid SSH journal evidence")
    first = min(map(int, values))
    if any(timestamp >= first for timestamp in timestamps.values()):
        raise RuntimeError("Service was not active before first observed SSH login")
    return {"unitActiveEnterMonotonic": timestamps,
            "firstObservedSshLoginMonotonic": first,
            "claim": "service active before first observed SSH login"}


def cleanup_owned_service(unit, uninstall, registration_exists, reconcile_absent,
                          restore_linger):
    """Resume exact uninstall, then prove the expected unit is fully absent."""
    if registration_exists():
        if not unit:
            raise RuntimeError("Boot unit identity is unknown; preserve linger and fixture")
        uninstall()
        if registration_exists():
            raise RuntimeError("Exact boot registration remains; preserve linger and fixture")
    if not unit or not reconcile_absent(unit):
        raise RuntimeError("Absent registration cannot be reconciled; preserve linger and fixture")
    restore_linger()


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "verify", "cleanup"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    token = str(uuid.UUID(args.run_id))
    root = args.root.resolve(strict=True)
    home = Path.home().resolve(strict=True)
    uid = os.geteuid()
    account = pwd.getpwuid(uid).pw_name
    if (sys.platform != "linux" or args.root.is_symlink() or root.parent != home
            or root.name != "lomi-product-" + token or root.stat().st_uid != uid
            or (root / ".fixture-marker").read_text() != token):
        raise RuntimeError("Invalid disposable fixture ownership")
    binary = root / "bin/lomiremote"
    profile = root / "s $%"
    registration = profile / "service-registration.json"
    journal = root / "boot-service-owner.json"
    env = {**os.environ, "PATH": "/usr/bin:/bin", "SHELL": "/bin/sh"}
    env.pop("XDG_CONFIG_HOME", None)

    def command(argv, expected=0, timeout=90):
        result = run_owned(argv, env=env, timeout=timeout)
        if result.returncode != expected:
            raise RuntimeError("Bound boot service command failed: " + str(result.returncode))
        return result.stdout

    def cli(*argv, expected=0):
        return command([str(binary), "--profile-dir", str(profile), *argv], expected)

    def load_owner():
        data = json.loads(journal.read_text())
        if data.get("profile") != str(profile) or data.get("uid") != uid:
            raise RuntimeError("Boot-service ownership journal mismatch; preserve fixture")
        if data.get("unit") != expected_unit(profile) or data.get("installAttempted") is not True:
            raise RuntimeError("Boot-service install ownership is incomplete; preserve fixture")
        return data

    def require_exact_registration(mode):
        reg = json.loads(registration.read_text())
        if not registration_matches(reg, profile, binary, account, mode, expected_unit(profile)):
            raise RuntimeError("Unexpected product boot registration; preserve fixture")
        return reg

    if args.phase == "prepare":
        if journal.exists() or profile.exists():
            raise RuntimeError("Boot-service fixture already exists; preserve fixture")
        # Persist the original state and restoration intent before any mutation.
        original = command(["/usr/bin/loginctl", "show-user", str(uid), "-p", "Linger", "--value"]).strip()
        if original not in ("yes", "no"):
            raise RuntimeError("Cannot establish original linger state")
        pre_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", pre_boot_id) is None:
            raise RuntimeError("Cannot establish valid pre-boot identity")
        unit = expected_unit(profile)
        journal.write_text(json.dumps({"profile": str(profile), "uid": uid,
                                       "originalLinger": original, "changedLinger": original == "no",
                                       "restorePending": original == "no", "preBootId": pre_boot_id,
                                       "unit": unit, "installAttempted": True}))
        journal.chmod(0o600)
        if original == "no":
            command(linger_mutation_command("enable-linger", uid))
        cli("service", "install", "--mode", "boot", "--account", str(uid))
        reg = require_exact_registration("boot")
        print(json.dumps({"phase": "prepare", "passed": True, "originalLinger": original,
                          "changedLinger": original == "no", "unit": unit}))
        return

    owner = load_owner()
    if args.phase == "verify":
        reg = json.loads(registration.read_text())
        unit = owner.get("unit")
        if (not unit or not registration_matches(reg, profile, binary, account, "boot", unit)):
            raise RuntimeError("Exact boot unit ownership cannot be confirmed")
        if command(["/usr/bin/loginctl", "show-user", str(uid), "-p", "Linger", "--value"]).strip() != "yes":
            raise RuntimeError("Linger did not survive cold boot")
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        require_changed_boot_id(owner.get("preBootId"), boot_id)
        units = ["user-runtime-dir@%s.service" % uid, "user@%s.service" % uid, unit]
        props = {}
        for name in units:
            scope = ["/usr/bin/systemctl"] if name in units[:2] else ["/usr/bin/systemctl", "--user"]
            props[name] = command(scope + ["show", name,
                                   "--property=ActiveEnterTimestampMonotonic", "--value"]).strip()
        events_raw = command(ssh_journal_command(), timeout=90)
        events = [json.loads(line) for line in events_raw.splitlines() if line]
        evidence = qualify_timestamps(boot_id, {units[0]: props[units[0]], units[1]: props[units[1]],
                                                   "product": props[unit]}, events, uid, account)
        print(json.dumps({"phase": "verify", "passed": True, "unit": unit,
                          "evidence": evidence}))
        return

    # Product uninstall safely stops a present exact unit and resumes partial installs.
    unit = owner.get("unit")
    if registration.exists():
        require_exact_registration("boot")
    def restore_linger():
        # Only restore a change made by this run, after stop/uninstall confirmation.
        if owner.get("changedLinger") is True:
            command(linger_mutation_command("disable-linger", uid))
            if command(["/usr/bin/loginctl", "show-user", str(uid), "-p", "Linger", "--value"]).strip() != owner["originalLinger"]:
                raise RuntimeError("Linger restoration unconfirmed; preserve fixture")

    def reconcile_absent(name):
        if name != unit:
            return False
        unit_file = Path.home() / ".config/systemd/user" / name
        wants_link = unit_file.parent / "default.target.wants" / name
        output = command(["/usr/bin/systemctl", "--user", "show", name,
                          "--property=LoadState", "--property=ActiveState",
                          "--property=MainPID", "--property=FragmentPath",
                          "--property=DropInPaths"])
        properties = {}
        for line in output.splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"LoadState", "ActiveState", "MainPID", "FragmentPath", "DropInPaths"}:
                properties[key] = value
        return absent_unit_confirmed(
            unit_file.exists() or unit_file.is_symlink(),
            wants_link.exists() or wants_link.is_symlink(), properties)

    cleanup_owned_service(unit,
                          lambda: cli("service", "uninstall"),
                          registration.exists,
                          reconcile_absent,
                          restore_linger)
    journal.unlink()
    print(json.dumps({"phase": "cleanup", "passed": True, "lingerRestored": owner.get("changedLinger") is True,
                      "unitRemoved": not registration.exists()}))


if __name__ == "__main__":
    main()
