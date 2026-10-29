"""The runner must never publish completion before prerequisite cleanup."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from run_linux_git_isolation_spike import finish_report


def check(error, expected):
    report = {"complete": False}
    saved = []

    def cleanup():
        raise error

    outcome = finish_report(report, 0, True, cleanup, lambda: saved.append(report.copy()))
    assert outcome == expected
    assert saved == [{"complete": False, "cleanupErrorClass": type(error).__name__}]


check(RuntimeError("injected cleanup failure"), 1)
check(KeyboardInterrupt(), 130)
report = {}
assert finish_report(report, 0, False, lambda: None, lambda: None) == 0
assert report["complete"]
print("runner cleanup failure and interruption: passed")
