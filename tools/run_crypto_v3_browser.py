#!/usr/bin/env python3
"""Bounded native/WASM/Chromium runtime experiment for canonical context v3."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from owned_process import initialize_process_ownership, run_owned


def main():
    initialize_process_ownership()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    artifacts=root/"artifacts/crypto-v3-browser"
    artifacts.mkdir(parents=True,exist_ok=True,mode=0o700)
    home=Path.home()
    cargo=home/".cargo/bin/cargo"
    bindgen=home/".cargo/bin/wasm-bindgen"
    node=shutil.which("node")
    if not node or not cargo.is_file() or not bindgen.is_file():parser.error("explicit installed Cargo, wasm-bindgen and Node required")
    # Deliberate tool paths only, no inherited credentials, tokens or dotenv.
    env={"HOME":str(home),"PATH":os.pathsep.join([str(cargo.parent),str(Path(node).parent),"/usr/bin","/bin"]),
         "CARGO_INCREMENTAL":"0","CARGO_PROFILE_DEV_DEBUG":"0",
         "CARGO_PROFILE_TEST_DEBUG":"0","CARGO_BUILD_JOBS":"2"}
    report={"scope":"unqualified-canonical-v3-browser-runtime","productionQualified":False,"passed":False,"checks":[],"not_run":["native Windows runtime","native mobile ABI","production authority/freshness","release pipeline","production deployment"]}
    exit_code=1
    def run(label,command,timeout=180):
        start=time.monotonic()
        try:result=run_owned(command,cwd=root,env=env,timeout=timeout)
        except BaseException as error:
            report["checks"].append({"step":label,"command":command,"exitCode":None,"outcome":"interrupted" if isinstance(error,KeyboardInterrupt) else "timeout" if isinstance(error,subprocess.TimeoutExpired) else "exception","durationSeconds":round(time.monotonic()-start,3)})
            raise
        report["checks"].append({"step":label,"command":command,"exitCode":result.returncode,"durationSeconds":round(time.monotonic()-start,3)})
        print(f"{label}: exit {result.returncode}")
        return result
    try:
        version=run("wasm-bindgen-version",[str(bindgen),"--version"],10)
        expected=re.search(r'wasm-bindgen = \{ version = "=([0-9.]+)"', (root/"crates/lomi-remote-crypto/Cargo.toml").read_text()).group(1)
        actual=version.stdout.strip().removeprefix("wasm-bindgen ")
        if version.returncode or actual!=expected:raise RuntimeError("wasm-bindgen CLI/crate mismatch")
        report["wasmBindgenVersion"]=actual
        nv=run("node-version",[node,"--version"],10)
        report["nodeVersion"]=nv.stdout.strip()
        if nv.returncode or report["nodeVersion"]!="v22.22.3":raise RuntimeError("unqualified Node version")
        pw=root/"packages/terminal-renderer/node_modules/@playwright/test/package.json"
        report["playwrightVersion"]=json.loads(pw.read_text())["version"]
        if report["playwrightVersion"]!="1.62.1":raise RuntimeError("unqualified Playwright version")
        (artifacts/"browser-results.json").unlink(missing_ok=True)
        commands=[
            ("native-v3-peer-build",[str(cargo),"build","--offline","--locked","-p","lomi-remote-crypto","--features","test-fixtures","--example","v3_browser_interop"]),
            ("debug-wasm-v3-build",[str(cargo),"build","--offline","--locked","-p","lomi-remote-crypto","--features","browser,test-fixtures","--target","wasm32-unknown-unknown","--lib"]),
            ("generate-web-wasm-bindings",[str(bindgen),"--target","web","--out-dir",str(artifacts/"wasm"),str(root/"target/wasm32-unknown-unknown/debug/lomi_remote_crypto.wasm")]),
            ("actual-chromium-native-wasm-v3",[node,str(root/"tests/crypto-v3-browser/browser.mjs"),str(artifacts/"wasm"),str(root/"target/debug/examples/v3_browser_interop"),str(artifacts/"browser-results.json")]),
        ]
        for label,command in commands:
            if run(label,command,120).returncode:return 1
        observed=json.loads((artifacts/"browser-results.json").read_text())
        report["browser"]=observed
        if not observed.get("passed") or not observed.get("cleanupCompleted"):return 1
        report["passed"]=True;exit_code=0
        return 0
    finally:
        report["exitCode"]=exit_code
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+"\n")


if __name__=="__main__":raise SystemExit(main())
