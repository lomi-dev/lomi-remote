#!/usr/bin/env python3
"""Explicit owned-run interruption/recovery proof; never signals a job PID."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from owned_process import initialize_process_ownership, run_owned, signal_group

BASE = Path.home() / ".lomi-coalition-artifacts"
DRIVER = Path(__file__).with_name("run_native.py")
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}


def run_case(phase, sig):
    previous = set(BASE.iterdir()) if BASE.exists() else set()
    child = subprocess.Popen([sys.executable, "-B", str(DRIVER), "--run-native", "--fixture-pause", phase],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             start_new_session=True, env=ENV)
    root = None
    try:
        deadline = time.monotonic() + 20
        paused = False
        while time.monotonic() < deadline:
            for candidate in set(BASE.iterdir()) - previous:
                try:
                    value = json.loads((candidate / "evidence.json").read_text())
                except (FileNotFoundError, json.JSONDecodeError):
                    continue
                if value.get("driverPid") == child.pid:
                    root = candidate
                    if value.get("fixturePause") == phase:
                        paused = True
                        break
            if paused:
                break
            # Observe without reaping, retaining group identity for the signal.
            status = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                raise RuntimeError("driver exited before fault hook")
            time.sleep(0.005)
        if not paused:
            raise RuntimeError("fault hook timeout")
        # A live runner's private run lock must exclude exact UUID recovery.
        excluded = run_owned([sys.executable, "-B", str(DRIVER), "--run-native", "--recover", root.name], env=ENV, timeout=5)
        if excluded.returncode == 0 or "run_is_active" not in excluded.stderr:
            raise RuntimeError("live recovery was not excluded")
        signal_group(child, sig)  # Guard verifies this exact child is unreaped.
        stdout, stderr = child.communicate(timeout=20)
        if child.returncode == 0:
            raise RuntimeError("interrupted run incorrectly passed")
        recovery = run_owned([sys.executable, "-B", str(DRIVER), "--run-native", "--recover", root.name], env=ENV, timeout=20)
        (root / "fault-driver.stdout.log").write_text(stdout)
        (root / "fault-driver.stderr.log").write_text(stderr)
        (root / "fault-recovery.stdout.log").write_text(recovery.stdout)
        (root / "fault-recovery.stderr.log").write_text(recovery.stderr)
        # Later idempotency recovery rewrites recovery.json after re-auditing.
        # Preserve the exact first successful recovery bytes for this proof.
        first_recovery = root / "fault-first-recovery.json"
        with first_recovery.open("xb") as stream:
            stream.write((root / "recovery.json").read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        first_recovery.chmod(0o400)
        result = json.loads(first_recovery.read_text())
        if recovery.returncode or not result.get("recoveryConfirmed") or not result.get("cleanupConfirmed") or result.get("passed"):
            raise RuntimeError("exact recovery unconfirmed")
        if any(job.get("after") != {"job": "absent", "plist": "absent", "profile": "absent", "override": None} for job in result["jobs"]):
            raise RuntimeError("post-recovery resources remain")
        receipt = {"phase": phase, "signal": sig, "ownedChildExit": child.returncode,
                   "liveRecoveryExcluded": True, "recoveryExit": recovery.returncode,
                   "cleanupConfirmed": True, "numericJobSignals": False,
                   "driverSourceSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "firstRecoveryReceipt": first_recovery.name,
                   "recoveryReceiptSha256": hashlib.sha256(first_recovery.read_bytes()).hexdigest()}
        (root / "fault-evidence.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(root / "fault-evidence.json")
    finally:
        # Cooperative expiry is bounded. Never send a signal using a reaped PID.
        if child.returncode is None:
            signal_group(child, signal.SIGTERM)
            child.communicate(timeout=20)
        if root is not None:
            # Idempotent exact-run recovery is attempted even if assertions fail.
            recovered = run_owned([sys.executable, "-B", str(DRIVER), "--run-native", "--recover", root.name], env=ENV, timeout=20)
            if recovered.returncode:
                raise RuntimeError("final exact-run recovery uncertain: " + str(root))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true")
    args = parser.parse_args()
    if not args.run_native or sys.platform != "darwin":
        parser.error("explicit --run-native on macOS is required")
    initialize_process_ownership()
    for phase, sig in (("results", signal.SIGTERM), ("results", signal.SIGKILL), ("exit-checkpoint", signal.SIGKILL)):
        run_case(phase, sig)
