#!/usr/bin/env python3
"""Exercise actual Better Auth 1.7.6 against a new isolated PG17 cluster."""
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
from urllib.parse import quote
from auth_baseline import private_cluster
from owned_process import initialize_process_ownership, run_owned


def main():
    initialize_process_ownership()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-bin",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    package=root/"packages/auth-binding-spike"
    pg=args.pg_bin.resolve()
    bun=shutil.which("bun")
    if not bun or any(not(pg/name).is_file() for name in ("initdb","postgres","pg_ctl","psql")):
        parser.error("Bun and PostgreSQL 17 binaries required")
    version=subprocess.check_output([str(pg/"postgres"),"--version"],text=True).strip()
    if not re.search(r"PostgreSQL\) 17\.",version):parser.error("PostgreSQL 17 required")
    # Never use caller DB configuration, app credentials or dotenv files.
    env={k:v for k,v in os.environ.items() if not k.startswith("PG") and not any(s in k for s in ("DATABASE_URL","AUTH_BINDING_","BETTER_AUTH_"))}
    env["PGPASSFILE"]=os.devnull
    env["ENROLLMENT_FIXTURE_BINARY"]=str(root/"target/debug/lomi-enrollment-fixtures")
    report={"scope":"actual-better-auth-isolated-binding-proof","productionQualified":False,"postgresVersion":version,"bunVersion":subprocess.check_output([bun,"--version"],text=True).strip(),"fsync":True,"shutdownAndCleanupCompleted":False,"checks":[],"not_run":["production auth-app routes and hooks","real user enrollment UI","mobile login protocol","host credentials/recovery integration","relay admission","deployment"]}
    exit_code=1
    def run(label,command,cwd=root,input_sql=None):
        start=time.monotonic()
        try:
            if input_sql is None:
                result=run_owned(command,cwd=cwd,env=env,timeout=180)
            else:
                result=subprocess.run(command,cwd=cwd,env=env,input=input_sql,text=True,capture_output=True,timeout=30)
        except BaseException as error:
            # Record attempted shutdown even when it never returns a process
            # status. Never retain exception payloads, command output or env.
            outcome = "interrupted" if isinstance(error, KeyboardInterrupt) else "timeout" if isinstance(error, subprocess.TimeoutExpired) else "exception"
            report["checks"].append({"step":label,"command":command,"exitCode":None,"outcome":outcome,"durationSeconds":round(time.monotonic()-start,3),"totals":[]})
            raise
        check={"step":label,"command":command,"exitCode":result.returncode,"durationSeconds":round(time.monotonic()-start,3)}
        check["totals"]=[line.strip() for line in (result.stdout+result.stderr).splitlines() if re.fullmatch(r"\s*(?:[0-9]+ (?:pass|fail)|[0-9]+ expect\(\) calls|Ran [0-9]+ tests across [0-9]+ files\. \[[0-9.]+[a-z]+\])\s*",line)]
        report["checks"].append(check)
        print(f"{label}: exit {result.returncode}")
        if result.returncode:
            # Retain only generic failure positions; never stdout/error bodies
            # that could include Better Auth tokens or SQL parameter values.
            clean=re.sub(r"\x1b\[[0-9;]*m", "", result.stdout+result.stderr)
            locations=re.findall(r"(?:binding\.test\.ts|auth\.ts|setup\.ts):\d+:\d+",clean)
            states=re.findall(r'code: [\"\']([0-9A-Z]{5})[\"\']',clean)
            if states: print("PostgreSQL states: "+", ".join(sorted(set(states))))
            labels=[label for label in ["column", "relation", "permission denied", "transaction", "constraint", "schema", "SyntaxError", "Cannot find", "beforeEach", "database", "expected"] if label in clean]
            print("failure categories: "+", ".join(labels))

        return result.returncode==0
    try:
        if not run("build-existing-canonical-proof-fixture",["cargo","build","--locked","-p","lomi-enrollment-fixtures"]):return 1
        if not run("frozen-exact-version-package-install",[bun,"--no-env-file","install","--frozen-lockfile"],package):return 1
        if not run("typecheck",[bun,"--no-env-file","run","typecheck"],package):return 1
        report["dependencyVersions"]={name:json.loads((package/"node_modules"/name/"package.json").read_text())["version"] for name in ("better-auth","@better-auth/core","@better-auth/kysely-adapter","kysely","pg","typescript")}
        report["pinnedSourceDigests"]={name:hashlib.sha256((package/"node_modules"/name).read_bytes()).hexdigest() for name in ("better-auth/dist/plugins/device-authorization/routes.mjs","@better-auth/kysely-adapter/dist/index.mjs")}
        with private_cluster() as base:
            data,sockets=base/"data",base/"socket"
            sockets.mkdir(mode=0o700);started=False;port="57447"
            try:
                psql=[str(pg/"psql"),"-X","--no-password","-h",str(sockets),"-p",port,"-U","e0_binding_owner","-v","ON_ERROR_STOP=1"]
                if not run("init-private-pg17",[str(pg/"initdb"),"-D",str(data),"-U","e0_binding_owner","--auth=trust","--no-locale","-E","UTF8"]):return 1
                if not run("start-socket-only-pg17-fsync-on",[str(pg/"pg_ctl"),"-D",str(data),"-l",str(base/"postgres.log"),"-o",shlex.join(["-h","","-k",str(sockets),"-p",port]),"-w","start"]):return 1
                started=True
                if not run("create-disposable-database",[*psql,"-d","postgres","-c","CREATE DATABASE auth_binding_test"]):return 1
                suffix=f"@localhost:{port}/auth_binding_test?host={quote(str(sockets),safe='')}"
                env["AUTH_BINDING_OWNER_URL"]="postgresql://e0_binding_owner"+suffix
                env["AUTH_BINDING_RUNTIME_URL"]="postgresql://e0_binding_runtime"+suffix
                if not run("actual-better-auth-generated-schema",[bun,"--no-env-file","run","setup.ts"],package):return 1
                grants="""
CREATE ROLE e0_binding_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE auth_binding_test TO e0_binding_runtime;
GRANT USAGE ON SCHEMA ba_fixture,auth_binding TO e0_binding_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA ba_fixture TO e0_binding_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA auth_binding TO e0_binding_runtime;
GRANT INSERT ON auth_binding.session_class TO e0_binding_runtime;
GRANT INSERT,UPDATE ON auth_binding.enrollment,auth_binding.bootstrap,auth_binding.host_authorization,auth_binding.consumer,auth_binding.window_key TO e0_binding_runtime;
GRANT UPDATE(state,epoch) ON auth_binding.policy TO e0_binding_runtime;
ALTER ROLE e0_binding_runtime SET statement_timeout='7s';
ALTER ROLE e0_binding_runtime SET idle_in_transaction_session_timeout='7s';
"""
                if not run("install-limited-experiment-runtime-role",[*psql,"-d","auth_binding_test"],input_sql=grants):return 1
                okay=run("actual-handler-pg-bindings-and-concurrency",[bun,"--no-env-file","test",str(root/"tests/auth-binding/binding.test.ts"),"--timeout","30000"],package)
                suite_passed=okay
            finally:
                if started or (data/"postmaster.pid").exists():
                    if not run("stop-private-pg17",[str(pg/"pg_ctl"),"-D",str(data),"-m","immediate","-w","stop"]):
                        exit_code=1;raise RuntimeError("uncertain PG stop; preserve private cluster")
        # Success is published only after both pg_ctl and private_cluster
        # cleanup have completed without timeout, interrupt or exception.
        report["shutdownAndCleanupCompleted"]=True
        exit_code=0 if suite_passed else 1
        return exit_code
    finally:
        report["exitCode"]=exit_code
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+"\n")


if __name__=="__main__":raise SystemExit(main())
