#!/usr/bin/env python3
"""Measure the pinned baseline relay against real PG17 authorization contention."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time
from datetime import datetime, timezone
from uuid import uuid4
from urllib.parse import quote

from auth_baseline import private_cluster
from owned_process import initialize_process_ownership, run_owned

ROOT = Path(__file__).resolve().parents[1]


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-bin", type=Path, required=True)
    parser.add_argument("--auth-repo", type=Path, default=ROOT.parent / "auth-app")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/authority-lock/evidence.json")
    args = parser.parse_args()
    report = {"scope": "baseline-relay-real-authorization-lock-load",
              "runId": uuid4().hex, "recordedAtUtc": datetime.now(timezone.utc).isoformat(),
              "productionQualified": False, "newProtocolQualified": False,
              "passed": False, "shutdownAndCleanupCompleted": False, "checks": []}
    report["inputSha256"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                             for name in ("tools/run_authority_lock_spike.py", "tests/authority-lock/bench.ts", "tests/authority-lock/lifecycle.mjs", "tests/authority-lock/lifecycle.test.mjs", "tests/authority-lock/source.json")}
    # Invalidate older success before any prerequisite/setup can fail.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    pg, auth = args.pg_bin.resolve(), args.auth_repo.resolve()
    bun = shutil.which("bun")
    if not bun or any(not (pg / name).is_file() for name in ("initdb", "postgres", "psql", "pg_ctl")):
        parser.error("installed Bun and explicit PG17 binaries required")
    version = subprocess.check_output([str(pg / "postgres"), "--version"], text=True, timeout=10).strip()
    if not re.search(r"PostgreSQL\) 17\.", version):
        parser.error("PG17 required")
    pins = json.loads((ROOT / "tests/authority-lock/source.json").read_text())
    for relative, expected in pins["files"].items():
        path = auth / relative
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            parser.error("baseline source/dependency pin mismatch")
    # The test imports pinned baseline sources, never the application entrypoint.
    # Bun's no-env-file and explicit URL exclude real application configuration.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("PG", "AUTHORITY_FIXTURE_"))
           and not any(word in key for word in ("DATABASE_URL", "BETTER_AUTH_", "REMOTE_"))}
    env["PGPASSFILE"] = os.devnull
    report.update(postgresVersion=version,
                  bunVersion=subprocess.check_output([bun, "--version"], text=True, timeout=10).strip(),
                  sourcePins=pins,
                  not_run=["new host/consumer authority routes", "production relay", "multi-host distributed load", "release qualification"])
    outcome = 1

    def run(name, argv, timeout=60):
        start = time.monotonic()
        check = {"step": name, "command": argv, "exitCode": None}
        report["checks"].append(check)
        try:
            result = run_owned(argv, cwd=ROOT, env=env, timeout=timeout)
            check["exitCode"] = result.returncode
            print(f"{name}: exit {result.returncode}", flush=True)
            if result.returncode:
                # No raw SQL errors, URLs, tickets, payloads or child output.
                locations = re.findall(r"bench\.ts:\d+:\d+", result.stdout + result.stderr)
                if locations:
                    check["failureLocations"] = sorted(set(locations))
            return result.returncode == 0
        except BaseException as error:
            check["outcome"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "timeout" if isinstance(error, subprocess.TimeoutExpired) else "exception"
            raise
        finally:
            check["durationSeconds"] = round(time.monotonic() - start, 3)

    try:
        with private_cluster() as base:
            data, sockets = base / "data", base / "socket"
            sockets.mkdir(mode=0o700)
            port = "57451"
            started = False
            try:
                if not run("init-private-pg17", [str(pg / "initdb"), "-D", str(data), "-U", "authority_owner", "--auth=trust", "--no-locale", "-E", "UTF8"]):
                    return 1
                if not run("start-socket-only-pg17-fsync-on", [str(pg / "pg_ctl"), "-D", str(data), "-l", str(base / "postgres.log"), "-o", shlex.join(["-h", "", "-k", str(sockets), "-p", port]), "-w", "start"]):
                    return 1
                started = True
                sql = """
CREATE ROLE authority_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE TABLE public.authority_fixture (
    id integer PRIMARY KEY CHECK (id=1), active boolean NOT NULL,
    epoch integer NOT NULL, owner text, expires_at timestamptz
);
INSERT INTO public.authority_fixture VALUES (1,true,0,NULL,NULL);
GRANT SELECT, UPDATE ON public.authority_fixture TO authority_runtime;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER ROLE authority_runtime SET statement_timeout='7s';
ALTER ROLE authority_runtime SET idle_in_transaction_session_timeout='10s';
"""
                schema = base / "fixture.sql"
                schema.write_text(sql)
                psql = [str(pg / "psql"), "-X", "--no-password", "-h", str(sockets), "-p", port, "-U", "authority_owner", "-d", "postgres", "-v", "ON_ERROR_STOP=1"]
                if not run("limited-runtime-schema", [*psql, "-f", str(schema)]):
                    return 1
                observations = base / "observations.json"
                env.update(AUTHORITY_FIXTURE_DATABASE_URL=f"postgresql://authority_runtime@localhost:{port}/postgres?host={quote(str(sockets), safe='')}",
                           AUTHORITY_FIXTURE_AUTH_REPO=str(auth), AUTHORITY_FIXTURE_OUTPUT=str(observations))
                success = run("actual-baseline-relay-pg-lock-budget", [bun, "--no-env-file", str(ROOT / "tests/authority-lock/bench.ts")], timeout=160)
                if observations.is_file():
                    report["observations"] = json.loads(observations.read_text())
                success = success and report.get("observations", {}).get("passed") is True and report.get("observations", {}).get("cleanupCompleted") is True
            finally:
                if started or (data / "postmaster.pid").exists():
                    if not run("stop-private-pg17", [str(pg / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"]):
                        raise RuntimeError("private cluster stop uncertain; files preserved")
        report["shutdownAndCleanupCompleted"] = True
        report["passed"] = bool(success)
        outcome = 0 if success else 1
        return outcome
    finally:
        report["exitCode"] = outcome
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
