#!/usr/bin/env python3
"""Run existing auth foundation tests on a new, socket-only PostgreSQL cluster.

Never connects to DATABASE_URL from the caller or loads application .env files.
This verifies the existing device flow; it does not implement host enrollment.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time
import re
from urllib.parse import quote
from owned_process import initialize_process_ownership, run_owned


def run(argv, cwd, env, timeout=120):
    started = time.monotonic()
    result = run_owned(argv, cwd=cwd, env=env, timeout=timeout)
    return result, {"command": argv, "exitCode": result.returncode,
                    "durationSeconds": round(time.monotonic() - started, 3)}


@contextmanager
def private_cluster():
    base = Path(tempfile.mkdtemp(prefix="lomi-e0-pg-", dir="/tmp"))
    try:
        yield base
    finally:
        # Preserve the cluster on an uncertain stop, including start timeouts.
        # TemporaryDirectory would remove it even while propagating an error.
        if (base / "data/postmaster.pid").exists():
            raise RuntimeError(f"private PostgreSQL may still be running; preserved at {base}")
        shutil.rmtree(base)


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auth-repo", type=Path, default=Path(__file__).resolve().parents[2] / "auth-app")
    parser.add_argument("--pg-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    auth = args.auth_repo.resolve()
    pg = args.pg_bin.resolve()
    bun = shutil.which("bun")
    if not bun or not (auth / "node_modules/prisma/build/index.js").is_file():
        parser.error("existing auth-app dependencies and Bun are required")
    for name in ("initdb", "pg_ctl", "psql"):
        if not (pg / name).is_file():
            parser.error("PostgreSQL binaries are incomplete")
    # Clear DB-related inherited configuration. This child cluster is the only
    # target; never read .pgpass or an application's .env for connection details.
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG") and k not in {"DATABASE_URL", "MIGRATION_DATABASE_URL"}}
    env["PGPASSFILE"] = os.devnull
    report = {"scope": "existing-auth-foundation-only", "newHostEnrollmentQualified": False,
              "checks": [], "postgresVersion": subprocess.check_output([str(pg / "postgres"), "--version"], text=True).strip(),
              "bunVersion": subprocess.check_output([bun, "--version"], text=True).strip()}
    started = False
    outcome = 1
    with private_cluster() as base:
        data = base / "data"
        sockets = base / "socket"
        sockets.mkdir(mode=0o700)
        port = "57439"  # Unix socket only, isolated by a unique private directory.
        url = f"postgresql://lomi_e0_owner@localhost:{port}/lomi_auth_test?host={quote(str(sockets), safe='')}"
        env.update(DATABASE_URL=url, MIGRATION_DATABASE_URL=url)
        startup = base / "synthetic-psqlrc"
        startup_marker = "LOMI_E0_SYNTHETIC_STARTUP_LOADED"
        startup.write_text(f"\\echo {startup_marker}\n")
        env["PSQLRC"] = str(startup)
        psql = [str(pg / "psql"), "-X", "--no-password", "-A", "-t", "-h", str(sockets),
                "-p", port, "-U", "lomi_e0_owner", "-d", "postgres", "-v", "ON_ERROR_STOP=1"]
        try:
            setup = [
                [str(pg / "initdb"), "-D", str(data), "-U", "lomi_e0_owner", "--auth=trust", "--no-locale", "-E", "UTF8"],
                [str(pg / "pg_ctl"), "-D", str(data), "-l", str(base / "postgres.log"), "-o",
                 shlex.join(["-h", "", "-k", str(sockets), "-p", port, "-F"]), "-w", "start"],
                [*psql, "-f", str(startup)],
                [*psql, "-c", "SELECT 1"],
                [*psql, "-c", "CREATE DATABASE lomi_auth_test"],
                [bun, "--no-env-file", "node_modules/prisma/build/index.js", "migrate", "deploy", "--config", "prisma.config.ts"],
            ]
            for index, command in enumerate(setup):
                result, check = run(command, auth, env)
                # Do not save stdout: Better Auth failures can include tokens.
                check["step"] = ("initdb", "start-private-postgres", "verify-synthetic-startup-marker", "ignore-synthetic-psqlrc", "create-fixture-database", "apply-existing-migrations")[index]
                valid = result.returncode == 0
                if index == 2:
                    check["startupMarkerObserved"] = startup_marker in result.stdout.splitlines()
                    valid = valid and check["startupMarkerObserved"]
                if index == 3:
                    check["startupMarkerAbsent"] = startup_marker not in result.stdout
                    check["selectSucceeded"] = result.stdout.strip() == "1"
                    valid = valid and check["startupMarkerAbsent"] and check["selectSucceeded"]
                check["assertionPassed"] = valid
                report["checks"].append(check)
                if index == 1 and result.returncode == 0:
                    started = True
                if not valid:
                    print(f"{check['step']}: failed (exit {result.returncode})")
                    return 1
            command = [bun, "--no-env-file", "test", "test/device-transaction.test.ts", "test/revocation-race.test.ts", "--timeout", "30000"]
            result, check = run(command, auth, env, timeout=180)
            check["step"] = "existing-device-and-revocation-tests"
            # Only test-runner totals are retained, never error bodies or tokens.
            check["totals"] = [line.strip() for line in (result.stdout + result.stderr).splitlines()
                               if re.fullmatch(r"\s*(?:[0-9]+ (?:pass|fail)|[0-9]+ expect\(\) calls|Ran [0-9]+ tests across [0-9]+ files\. \[[0-9.]+[a-z]+\])\s*", line)]
            report["checks"].append(check)
            print(f"existing auth foundation: exit {result.returncode}")
            for line in check["totals"]:
                print(line)
            outcome = result.returncode
        finally:
            if started or (data / "postmaster.pid").exists():
                result, check = run([str(pg / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"], auth, env)
                check["step"] = "stop-private-postgres"
                report["checks"].append(check)
                if result.returncode:
                    # Keep a still-running cluster instead of deleting its files.
                    raise RuntimeError("private cluster did not stop; refuse cleanup")
            report["exitCode"] = outcome
            # URI uses only synthetic identity/private socket, no credentials.
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n")
    return outcome


if __name__ == "__main__":
    raise SystemExit(main())
