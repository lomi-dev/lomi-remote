"""Independent bounded lifecycle cleanup and unconditional failed evidence."""
import json
from pathlib import Path


def finish(report, steps, evidence):
    errors = []
    try:
        for name, action in steps:
            try:
                action()
            except BaseException as error:
                errors.append({"step": name, "error": type(error).__name__})
    finally:
        report["cleanupErrors"] = errors
        report["cleanupCompleted"] = not errors
        report["passed"] = report.get("passed", False) and not errors
        # This outermost write still executes if any cleanup action is interrupted.
        Path(evidence).write_text(json.dumps(report, indent=2) + "\n")


def require_clean_exit(process, report, timeout=5):
    code = process.wait(timeout=timeout)
    report["desktopExit"] = {"code": code if code >= 0 else None,
                             "signal": -code if code < 0 else None,
                             "forcedCleanup": False}
    if code != 0:
        raise RuntimeError("isolated native process did not exit successfully")
