#!/usr/bin/env python3
"""Fresh evidence before setup; bounded ownership of the browser fixture process."""
import argparse
import datetime
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]


def persist(path, report):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f"evidence.{report['attemptId']}.tmp")
    with temporary.open("w") as stream:
        os.chmod(temporary, 0o600)
        json.dump(report, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, default=ROOT / "artifacts/protocol-browser/evidence.json")
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--hold-after-ready", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.evidence.resolve()
    report = {"kind": "canonical-protocol-actual-browser", "attemptId": str(uuid.uuid4()),
              "startedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "phase": "starting", "complete": False, "passed": False, "qualified": False}
    # This synchronous prelude precedes project helper imports and Node startup.
    persist(output, report)
    marker = output.with_name(f"cancel.{report['attemptId']}")
    cancelled = False

    def cancel(_signum, _frame):
        nonlocal cancelled
        cancelled = True
        marker.touch(mode=0o600)

    previous = {sig: signal.signal(sig, cancel) for sig in (signal.SIGINT, signal.SIGTERM)}
    status = 1
    cleanup = True
    reaped = False
    failure_class = None
    try:
        sys.path.insert(0, str(ROOT / "tools"))
        from owned_process import initialize_process_ownership, run_owned
        initialize_process_ownership()
        environment = dict(os.environ, LOMI_PROTOCOL_BROWSER_EVIDENCE=str(output),
                           LOMI_PROTOCOL_BROWSER_ATTEMPT=report["attemptId"],
                           LOMI_PROTOCOL_BROWSER_CANCEL=str(marker),
                           LOMI_PROTOCOL_BROWSER_HOLD="1" if args.hold_after_ready else "0")
        result = run_owned(["node", "tests/protocol-browser/browser.mjs"], cwd=ROOT,
                           env=environment, timeout=args.timeout)
        status = result.returncode
        reaped = True
    except subprocess.TimeoutExpired:
        failure_class = "Deadline"
        reaped = True
    except Exception:
        failure_class = "RunnerFailure"
    finally:
        try:
            candidate = json.loads(output.read_text())
            if candidate.get("attemptId") == report["attemptId"]:
                report.update(candidate)
        except (OSError, ValueError):
            cleanup = False
        if failure_class:
            report.update(errorClass=failure_class, phase="timed-out" if failure_class == "Deadline" else "failed")
        if cancelled:
            report.update(interrupted=True, phase="interrupted")
        passed = status == 0 and not cancelled and report.get("complete") is True and cleanup
        report.update(passed=passed, complete=passed, exitCode=0 if passed else 1)
        report["wrapper"] = {"deadlineSeconds": args.timeout, "childReaped": reaped,
                             "interruptionObserved": cancelled}
        persist(output, report)
        marker.unlink(missing_ok=True)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print("passed: actual Chromium canonical contract parity" if report["passed"] else
          "failed: Chromium protocol attempt is incomplete")
    return report["exitCode"]


if __name__ == "__main__":
    sys.exit(main())
