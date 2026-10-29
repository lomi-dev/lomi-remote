#!/usr/bin/env python3
"""Synthetic qualification in the explicitly selected disposable Linux VM only."""
import argparse
import fcntl
import hashlib
import stat
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

USER = "lomi-service"
UID = 2001
HOME = Path("/var/lib/lomi-service-fixture")
STATE = HOME / "state"
BIN = "/usr/local/libexec/lomi-service-fixture"
UNIT = "lomi-service-fixture.service"
CHECKPOINT = Path("/var/lib/lomi-service-fixture-checkpoint.json")
checks = []


def run(argv, *, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError("guest command failed: " + Path(argv[0]).name)
    return result


def as_user(*args, check=True):
    return run(["runuser", "-u", USER, "--", "env", "-i", "HOME=" + str(HOME),
                "PATH=/usr/bin:/bin", "LC_ALL=C", "XDG_RUNTIME_DIR=/run/user/2001",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/2001/bus", *args], check=check)


def control(*args, check=True):
    return as_user("systemctl", "--user", *args, check=check)


def client(command="status", check=True):
    result = as_user(BIN, "client", str(STATE), command, check=check)
    return json.loads(result.stdout) if result.returncode == 0 else None


def until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = client(check=False)
            if value is not None and predicate(value):
                return value
        except (RuntimeError, json.JSONDecodeError):
            pass
        time.sleep(.05)
    raise RuntimeError("synthetic fixture condition timeout")


def require(label, passed):
    checks.append({"id": label, "passed": bool(passed)})
    if not passed:
        raise RuntimeError("check failed: " + label)


def ready():
    return until(lambda s: s["state"] == "running" and s["stats"]["ready"] and
                 s["stats"]["cwdDetected"] and s["stats"]["workerPid"] is not None)


def absent(pid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not Path(f"/proc/{pid}").exists():
            return True
        time.sleep(.05)
    return False


def stopped(previous, label):
    require(label + "_shell_reaped", absent(previous["childPid"]))
    require(label + "_worker_reaped", absent(previous["stats"]["workerPid"]))


def private_dir(path):
    path.mkdir(exist_ok=True)
    os.chown(path, UID, UID)
    path.chmod(0o700)


def install(binary, unit):
    try:
        user = pwd.getpwnam(USER)
    except KeyError:
        run(["useradd", "--uid", str(UID), "--create-home", "--home-dir", str(HOME),
             "--shell", "/usr/sbin/nologin", USER])
        user = pwd.getpwnam(USER)
    require("dedicated_nologin_account_distinct_from_ssh_user",
            user.pw_uid == UID and user.pw_dir == str(HOME) and user.pw_shell == "/usr/sbin/nologin" and pwd.getpwnam("lomi-e0").pw_uid != UID)
    private_dir(HOME)
    Path("/usr/local/libexec").mkdir(exist_ok=True)
    shutil.copyfile(binary, BIN)
    os.chmod(BIN, 0o755)
    for path in [HOME / ".config", HOME / ".config/systemd", HOME / ".config/systemd/user"]:
        private_dir(path)
    installed = HOME / ".config/systemd/user" / UNIT
    shutil.copyfile(unit, installed)
    os.chown(installed, UID, UID)
    installed.chmod(0o600)
    run(["loginctl", "enable-linger", USER])
    run(["systemctl", "start", f"user@{UID}.service"])
    control("daemon-reload")
    control("enable", "--now", UNIT)
    require("user_unit_enabled", control("is-enabled", UNIT).stdout.strip() == "enabled")
    require("linger_enabled", run(["loginctl", "show-user", USER, "-p", "Linger", "--value"]).stdout.strip() == "yes")
    require("user_unit_restart_on_failure", control("show", UNIT, "-p", "Restart", "--value").stdout.strip() == "on-failure")
    require("user_unit_kill_mode_control_group", control("show", UNIT, "-p", "KillMode", "--value").stdout.strip() == "control-group")


def prepare(args):
    install(args.binary, args.unit)
    initial = until(lambda s: s["state"] in ["idle", "lost"])
    require("service_owner_starts_without_implicit_pty", initial["childPid"] is None and initial["requiresExplicitStart"])
    client("start")
    first = ready()
    a, b = client(), client()
    require("two_separate_clients_observe_same_live_pty", a["sessionEpoch"] == b["sessionEpoch"] and a["childPid"] == b["childPid"])
    require("host_detects_osc7_cwd_without_renderer", first["stats"]["cwdDetected"])
    require("bounded_output_model_counters_advance", first["stats"]["outputBytes"] > 0 and first["stats"]["modelNonemptyCells"] > 0)
    second = as_user(BIN, "owner", str(STATE), check=False)
    require("second_owner_rejected", second.returncode != 0 and client()["ownerEpoch"] == first["ownerEpoch"])
    client("after-detach")
    until(lambda s: s["stats"]["detachObserved"])
    require("pty_survives_client_process_disconnect", client()["childPid"] == first["childPid"])
    client("resize")
    resized = until(lambda s: s["stats"]["resizeObserved"])
    require("native_stty_observes_37x101", resized["modelRows"] == 37 and resized["modelCols"] == 101)
    client("ctrl-c")
    exited = until(lambda s: s["state"] == "exited" and s["stats"]["ctrlCObserved"] and s["stats"]["cleanupComplete"])
    require("pty_ctrl_c_and_ordered_exit", exited["stats"]["exitCode"] == 0)
    stopped(first, "ctrl_c")
    client("start")
    clean = ready()
    require("explicit_new_start_uses_new_epoch_without_input_replay", clean["sessionEpoch"] != first["sessionEpoch"] and clean["stats"]["inputWrites"] == 0 and not clean["stats"]["detachObserved"])
    control("stop", UNIT)
    stopped(clean, "intentional_stop")
    time.sleep(1.5)
    require("intentional_stop_does_not_autorespawn", control("is-active", UNIT, check=False).stdout.strip() == "inactive")
    control("start", UNIT)
    lost = until(lambda s: s["state"] == "lost")
    require("owner_restart_marks_old_session_lost", lost["sessionEpoch"] == clean["sessionEpoch"] and lost["childPid"] is None and lost["stats"] is None)
    client("start")
    running = ready()
    control("restart", UNIT)
    stopped(running, "explicit_service_restart")
    lost = until(lambda s: s["state"] == "lost")
    require("service_restart_never_adopts_old_pid", lost["sessionEpoch"] == running["sessionEpoch"] and lost["ownerEpoch"] != running["ownerEpoch"] and lost["childPid"] is None)
    client("start")
    running = ready()
    control("kill", "--kill-whom=main", "--signal=KILL", UNIT)
    lost = until(lambda s: s["state"] == "lost" and s["ownerEpoch"] != running["ownerEpoch"])
    stopped(running, "failed_owner_restart")
    require("restart_on_failure_restarts_owner_only", lost["sessionEpoch"] == running["sessionEpoch"] and lost["childPid"] is None)
    client("start")
    final = ready()
    checkpoint = {"bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                  "ownerEpoch": final["ownerEpoch"], "sessionEpoch": final["sessionEpoch"],
                  "childPid": final["childPid"], "workerPid": final["stats"]["workerPid"]}
    CHECKPOINT.write_text(json.dumps(checkpoint))
    CHECKPOINT.chmod(0o600)


def after_disconnect():
    checkpoint = json.loads(CHECKPOINT.read_text())
    status = ready()
    require("live_pty_survives_completed_admin_ssh_session", status["ownerEpoch"] == checkpoint["ownerEpoch"] and status["sessionEpoch"] == checkpoint["sessionEpoch"] and status["childPid"] == checkpoint["childPid"])
    require("service_account_has_no_login_session", run(["loginctl", "show-user", USER, "-p", "Sessions", "--value"]).stdout.strip() == "")


def after_reboot():
    checkpoint = json.loads(CHECKPOINT.read_text())
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    require("actual_vm_boot_id_changed", boot != checkpoint["bootId"])
    require("linger_survives_reboot", run(["loginctl", "show-user", USER, "-p", "Linger", "--value"]).stdout.strip() == "yes")
    status = until(lambda s: s["state"] == "lost")
    require("enabled_user_unit_starts_after_boot_without_service_login", control("is-active", UNIT).stdout.strip() == "active" and run(["loginctl", "show-user", USER, "-p", "Sessions", "--value"]).stdout.strip() == "")
    require("reboot_reports_old_epoch_lost_without_pid_adoption", status["sessionEpoch"] == checkpoint["sessionEpoch"] and status["ownerEpoch"] != checkpoint["ownerEpoch"] and status["childPid"] is None and status["stats"] is None)
    require("boot_service_start_timestamp_present", int(control("show", UNIT, "-p", "ExecMainStartTimestampMonotonic", "--value").stdout.strip()) > 0)
    journal = run(["journalctl", "-b", "--no-pager", "--output=json", "USER_UNIT=" + UNIT], check=False)
    records = [json.loads(line) for line in journal.stdout.splitlines() if line.strip().startswith("{")]
    require("journal_records_unit_start_in_current_boot", any(r.get("_BOOT_ID") == boot.replace("-", "") for r in records))
    client("start")
    fresh = ready()
    require("explicit_post_boot_start_gets_new_epoch_and_no_replayed_input", fresh["sessionEpoch"] != checkpoint["sessionEpoch"] and fresh["stats"]["inputWrites"] == 0 and not fresh["stats"]["detachObserved"])
    client("exit")
    until(lambda s: s["state"] == "exited" and s["stats"]["cleanupComplete"])
    require("explicit_synthetic_exit_after_reboot", True)


def cleanup():
    try:
        control("disable", "--now", UNIT, check=False)
        unit = HOME / ".config/systemd/user" / UNIT
        if unit.exists():
            unit.unlink()
        control("daemon-reload", check=False)
        run(["loginctl", "disable-linger", USER], check=False)
        run(["systemctl", "stop", f"user@{UID}.service"], check=False)
        require("fixture_user_manager_stopped", run(["systemctl", "is-active", f"user@{UID}.service"], check=False).stdout.strip() == "inactive")
        require("fixture_unit_file_removed", not unit.exists())
        require("fixture_linger_marker_removed", not (Path("/var/lib/systemd/linger") / USER).exists())
        live = []
        for process in Path("/proc").iterdir():
            if process.name.isdigit():
                try:
                    if process.stat().st_uid == UID:
                        live.append(process.name)
                except FileNotFoundError:
                    pass
        require("fixture_account_has_no_remaining_processes", not live)
    except KeyError:
        require("fixture_account_not_created", True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["prepare", "after-disconnect", "after-reboot", "cleanup"])
    parser.add_argument("--disposable-vm", required=True, choices=["lomi-e0"])
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--unit", type=Path)
    parser.add_argument("--invocation-id")
    parser.add_argument("--deadline-unix", type=float)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
        raise SystemExit("This fixture may run only as root inside the explicitly selected disposable systemd Linux VM")
    report = {"phase": args.phase, "fixture": True, "qualifiedProductHost": False, "checks": checks,
              "invocationId": args.invocation_id, "probeSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    lock = None
    try:
        if args.deadline_unix is not None and time.time() >= args.deadline_unix:
            raise RuntimeError("guest phase deadline elapsed before execution")
        lock = os.open("/run/lomi-service-fixture-phase.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        metadata = os.fstat(lock)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RuntimeError("invalid guest phase lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.deadline_unix is not None and time.time() >= args.deadline_unix:
            raise RuntimeError("guest phase deadline elapsed before lock acquisition")
        if args.phase == "prepare":
            prepare(args)
        elif args.phase == "after-disconnect":
            after_disconnect()
        elif args.phase == "after-reboot":
            after_reboot()
        else:
            cleanup()
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["errorClass"] = type(error).__name__
        # Check labels identify failures without PTY, argv, environment or journal dumps.
    finally:
        if lock is not None:
            os.close(lock)
    report["completed"] = True
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
