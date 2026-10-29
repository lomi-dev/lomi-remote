#!/usr/bin/env python3
"""Reproduce synthetic Rust-grid projection evidence; never qualify the profile."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

from owned_process import initialize_process_ownership, run_owned

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts/terminal-state"
VERSION_COMMANDS = {"rustc": ["rustc", "--version"], "cargo": ["cargo", "--version"],
                    "node": ["node", "--version"]}
# Tool discovery/cache/temp locations only. No Node preload, Rust wrapper,
# database credential or terminal/session environment is passed to the fixtures.
ENVIRONMENT_KEYS = ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR", "TMP", "TEMP")


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=180,
                        help="positive deadline in seconds for each fixture/oracle command")
    parser.add_argument("--interactive", action="store_true",
                        help="run real synthetic Vim PTY milestones and project those states")
    args = parser.parse_args()
    if not 0 < args.timeout <= 600:
        parser.error("timeout must be greater than zero and at most 600 seconds")
    env = {key: os.environ[key] for key in ENVIRONMENT_KEYS if key in os.environ}
    env.update({"LC_ALL": "C", "TERM": "dumb", "CARGO_INCREMENTAL": "0",
                "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                "CARGO_BUILD_JOBS": "2"})
    report = {
        "kind": "interactive-vim-state-projection" if args.interactive else "synthetic-terminal-state-projection", "qualified": False,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "environment": {"os": platform.platform(), "machine": platform.machine(),
                        "python": platform.python_version()},
        "environmentPolicy": "allowlisted tool/cache/temp locations; values omitted",
        "checks": [], "complete": False, "regressionsPassed": False,
        "not_run": ["arbitrary CLI compatibility", "multi-hour soak",
                    "all browser/platform rendering", "production qualification"],
    }
    if not args.interactive:
        report["not_run"].append("native interactive lifecycle")
    artifacts = ARTIFACTS / "interactive" if args.interactive else ARTIFACTS
    artifacts.mkdir(parents=True, exist_ok=True)
    fixture = artifacts / "synthetic-fixtures.json"
    evidence = artifacts / "evidence.json"
    # An interrupted/failed new run must never consume a previous run's fixture.
    fixture.unlink(missing_ok=True)
    exit_code = 1
    current = None

    def save():
        evidence.write_text(json.dumps(report, indent=2) + "\n")

    def invoke(name, argv, timeout):
        nonlocal current
        current = {"name": name, "argv": argv, "cwd": str(ROOT),
                   "timeoutSeconds": timeout, "exitCode": None,
                   "durationSeconds": None, "status": "running"}
        report["checks"].append(current)
        save()
        started = time.monotonic()
        try:
            result = run_owned(argv, cwd=ROOT, env=env, timeout=timeout)
            current.update({"exitCode": result.returncode,
                            "status": "passed" if result.returncode == 0 else "failed"})
            return result
        except BaseException as error:
            current["status"] = ("timeout" if isinstance(error, subprocess.TimeoutExpired)
                                 else "interrupted" if isinstance(error, KeyboardInterrupt) else "failed")
            current["errorClass"] = type(error).__name__
            raise
        finally:
            current["durationSeconds"] = round(time.monotonic() - started, 3)
            save()

    try:
        for name, argv in VERSION_COMMANDS.items():
            result = invoke(f"version-{name}", argv, 10)
            if result.returncode:
                return 1
            # These commands emit version strings only; no environment values.
            report["environment"][name] = result.stdout.strip()
        argv = (["cargo", "run", "--locked", "--quiet", "-p", "lomi-terminal-pty-fixture",
                 "--", "--fixtures", str(fixture)] if args.interactive else
                ["cargo", "run", "--locked", "--quiet", "-p", "lomi-terminal-state",
                 "--bin", "state-fixtures"])
        result = invoke("interactive-vim-states" if args.interactive else "emit-rust-synthetic-states",
                        argv, args.timeout)
        if result.returncode:
            return 1
        # Parsing rejects incomplete/non-JSON output before making it available
        # to the oracle. Neither success output nor diagnostics are printed here.
        if args.interactive:
            observation = json.loads(result.stdout)
            if (observation.get("qualified") is not False or observation.get("cleanExit") is not True
                    or observation.get("childGroupGone") is not True
                    or observation.get("rawPtyClientWrites") != 0
                    or observation.get("syntheticFixtureUnchanged") is not True
                    or len(observation.get("milestones", [])) != 7):
                raise ValueError("incomplete interactive fixture observation")
            current["observation"] = observation
            payload = json.loads(fixture.read_text())
        else:
            payload = json.loads(result.stdout)
        if not isinstance(payload, dict) or payload.get("qualified") is not False:
            raise ValueError("fixture must explicitly remain unqualified")
        fixture.write_text(json.dumps(payload, separators=(",", ":")) + "\n")
        current["artifact"] = fixture.relative_to(ROOT).as_posix()
        result = invoke("project-rust-states-into-xterm", ["node", "tests/terminal-state/rust-oracle.mjs",
                        str(fixture)], args.timeout)
        if result.returncode:
            return 1
        # Whitelist the oracle's aggregate line; do not persist arbitrary terminal
        # payloads, traces or stdout/stderr from a failed command.
        aggregate = result.stdout.strip()
        if not re.fullmatch(r"passed: [0-9]+ Rust fixture cases, [0-9]+ full-grid/mode projections, "
                            r"[0-9]+ attachment boundaries; profile remains experimental", aggregate):
            raise ValueError("unexpected oracle aggregate")
        current["aggregate"] = aggregate
        print(aggregate, flush=True)
        report["complete"] = True
        report["regressionsPassed"] = True
        exit_code = 0
    except subprocess.TimeoutExpired:
        report["errorClass"] = "TimeoutExpired"
        exit_code = 124
        print("terminal state runner timed out; evidence remains incomplete", file=sys.stderr)
    except KeyboardInterrupt:
        report["errorClass"] = "KeyboardInterrupt"
        exit_code = 130
        print("terminal state runner interrupted; evidence remains incomplete", file=sys.stderr)
    except Exception as error:
        report["errorClass"] = type(error).__name__
        print(f"terminal state runner failed: {type(error).__name__}", file=sys.stderr)
    finally:
        report["exitCode"] = exit_code
        if exit_code:
            fixture.unlink(missing_ok=True)
        save()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
