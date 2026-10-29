#!/usr/bin/env python3
"""Run only the synthetic E0 enrollment store in a new private PG17 cluster."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import subprocess
import time
from urllib.parse import quote
from auth_baseline import private_cluster
from owned_process import initialize_process_ownership, run_owned


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    package = root / "packages/enrollment-spike"
    pg = args.pg_bin.resolve()
    bun = shutil.which("bun")
    if not bun or any(not (pg / p).is_file() for p in ("initdb", "postgres", "pg_ctl", "psql")):
        parser.error("Bun and PG17 binaries required")
    version = subprocess.check_output([str(pg / "postgres"), "--version"], text=True).strip()
    if not re.search(r"PostgreSQL\) 17\.", version):
        parser.error("this experiment requires PostgreSQL 17")
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG") and k not in {
        "DATABASE_URL", "MIGRATION_DATABASE_URL", "ENROLLMENT_TEST_URL", "ENROLLMENT_OWNER_URL", "ENROLLMENT_RECOVERY_KEY"}}
    env["PGPASSFILE"] = os.devnull
    report = {"scope": "synthetic-enrollment-store-only", "qualified": False,
              "postgresVersion": version,
              "environment": {"os": platform.platform(), "machine": platform.machine(),
                              "python": platform.python_version(), "postgres": version},
              "checks": [],
              "not_run": ["BetterAuth hook/class binding", "consumer FK/window lifecycle", "OS credential receipt", "production routes", "deployment"]}
    for name, command in {"bun": [bun, "--version"], "cargo": ["cargo", "--version"],
                          "rustc": ["rustc", "--version"]}.items():
        observed = run_owned(command, cwd=root, env=env, timeout=10)
        report["environment"][name] = observed.stdout.strip() if observed.returncode == 0 else "unavailable"
    result_code = 1
    def run(label, command, cwd=root, timeout=180, stdin=None):
        start = time.monotonic()
        if stdin is not None:
            # psql input contains synthetic role/DDL only, never tokens.
            result = subprocess.run(command, cwd=cwd, env=env, input=stdin, text=True, capture_output=True, timeout=timeout)
        else:
            result = run_owned(command, cwd=cwd, env=env, timeout=timeout)
        check = {"step": label, "argv": list(command), "cwd": str(cwd),
                 "timeoutSeconds": timeout, "exitCode": result.returncode,
                 "durationSeconds": round(time.monotonic()-start, 3)}
        check["totals"] = [s.strip() for s in (result.stdout + result.stderr).splitlines()
                           if re.fullmatch(r"\s*(?:[0-9]+ (?:pass|fail)|[0-9]+ expect\(\) calls|Ran [0-9]+ tests across [0-9]+ files\. \[[0-9.]+[a-z]+\])\s*", s)]
        report["checks"].append(check)
        print(f"{label}: exit {result.returncode}")
        return result.returncode == 0
    try:
        if not run("build-canonical-rust-fixture", ["cargo", "build", "--locked", "-p", "lomi-enrollment-fixtures"]):
            return 1
        env["ENROLLMENT_FIXTURE_BINARY"] = str(root / "target/debug/lomi-enrollment-fixtures")
        if not run("frozen-package-install", [bun,"--no-env-file","install","--frozen-lockfile"], package):
            return 1
        if not run("typecheck", [bun,"--no-env-file","run","typecheck"], package):
            return 1
        with private_cluster() as base:
            data, sockets = base / "data", base / "socket"
            sockets.mkdir(mode=0o700)
            port = "57443"
            started = False
            try:
                psql = [str(pg / "psql"), "-X", "--no-password", "-h", str(sockets), "-p", port, "-U", "e0_owner", "-v", "ON_ERROR_STOP=1"]
                if not run("init-private-pg17", [str(pg / "initdb"), "-D", str(data), "-U", "e0_owner", "--auth=trust", "--no-locale", "-E", "UTF8"]):
                    return 1
                # fsync remains enabled: crash tests must not use pg_ctl -F.
                if not run("start-private-socket-only-pg17", [str(pg / "pg_ctl"), "-D", str(data), "-l", str(base / "postgres.log"), "-o", shlex.join(["-h","","-k",str(sockets),"-p",port]), "-w", "start"]):
                    return 1
                started = True
                if not run("create-disposable-database", [*psql,"-d","postgres","-c","CREATE DATABASE lomi_enrollment_test"]):
                    return 1
                if not run("apply-experiment-schema", [*psql,"-d","lomi_enrollment_test","-f",str(package / "schema.sql")]):
                    return 1
                grants = """
CREATE ROLE e0_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE lomi_enrollment_test TO e0_runtime;
GRANT USAGE ON SCHEMA enrollment_spike TO e0_runtime;
GRANT SELECT, UPDATE ON enrollment_spike.account TO e0_runtime;
GRANT SELECT ON enrollment_spike.enrollment TO e0_runtime;
GRANT UPDATE(consumed_operation) ON enrollment_spike.enrollment TO e0_runtime;
GRANT SELECT, INSERT, UPDATE ON enrollment_spike.family, enrollment_spike.credential TO e0_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment_spike.recovery TO e0_runtime;
ALTER ROLE e0_runtime SET statement_timeout='5s';
ALTER ROLE e0_runtime SET idle_in_transaction_session_timeout='5s';
"""
                if not run("configure-limited-runtime-role", [*psql,"-d","lomi_enrollment_test"], stdin=grants):
                    return 1
                suffix=f"@localhost:{port}/lomi_enrollment_test?host={quote(str(sockets),safe='')}"
                env["ENROLLMENT_TEST_URL"]="postgresql://e0_runtime"+suffix
                env["ENROLLMENT_OWNER_URL"]="postgresql://e0_owner"+suffix
                env["ENROLLMENT_RECOVERY_KEY"]=secrets.token_hex(32)
                okay=run("postgres-enrollment-race-and-process-crash-tests", [bun,"--no-env-file","test",str(root / "tests/enrollment/store.test.ts"),"--timeout","30000"],package)
                result_code=0 if okay else 1
            finally:
                if started or (data / "postmaster.pid").exists():
                    if not run("stop-private-pg17", [str(pg / "pg_ctl"),"-D",str(data),"-m","immediate","-w","stop"]):
                        result_code = 1
                        raise RuntimeError("private cluster uncertain; preserve files")
        return result_code
    finally:
        report["exitCode"]=result_code
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+"\n")


if __name__ == "__main__":
    raise SystemExit(main())
