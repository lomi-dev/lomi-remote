#!/usr/bin/env python3
"""Opt-in macOS native S0.3 fixture; no product installation or accounts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests/desktop-e0"))
import build_receipt
sys.path.insert(0, str(Path(__file__).resolve().parent))
from owned_process import initialize_process_ownership, run_owned

REPO = Path(__file__).resolve().parents[1]
AUDIT = "2cef452c39eb8b455c8d2ae1251310dc870c50bb"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def atomic(path, value):
    temporary = path.with_suffix(".next")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream)
    temporary.replace(path)


def stop(child):
    if child and child.poll() is None:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)


def cleanup_fixture(report, root, appdata, home, children, fixture_pids, log=None, exit_native=None):
    """Attempt every owned cleanup action and always persist the failure receipt."""
    errors = []
    def attempt(label, action):
        try:
            action()
        except Exception as error:
            errors.append({"step": label, "error": type(error).__name__ + ": " + str(error)})
    try:
        host, native, vite_process = children
        if host and host.stdin:
            attempt("close host input", host.stdin.close)
        attempt("stop host", lambda: stop(host))
        if native and native.poll() is None and exit_native:
            def request_exit():
                try:
                    exit_native()
                except Exception:
                    # The native process can exit successfully before its final
                    # reply is observed; its actual exit still confirms success.
                    if native.poll() != 0:
                        raise
            attempt("request native exit", request_exit)
        attempt("stop native", lambda: stop(native))
        attempt("stop vite", lambda: stop(vite_process))
        def alive(pid):
            try:
                os.kill(pid, 0)
                return True
            except ProcessLookupError:
                return False
        ptys_terminated = False
        def check_ptys():
            nonlocal ptys_terminated
            for _ in range(50):
                if not any(alive(pid) for pid in fixture_pids):
                    ptys_terminated = True
                    return
                time.sleep(.1)
        attempt("confirm PTY termination", check_ptys)
        if log:
            attempt("close fixture log", log.close)
        attempt("remove exclusive appdata", lambda: shutil.rmtree(appdata))
        attempt("remove private home", lambda: shutil.rmtree(home))
        reaped = all(p is None or p.poll() is not None for p in children)
        report["cleanup"] = {"ownedProcessesReaped": reaped,
            "exclusiveAppdataRemoved": not appdata.exists(), "privateHomeRemoved": not home.exists(),
            "nativePtyPids": fixture_pids, "nativePtysTerminated": ptys_terminated, "errors": errors}
        if errors or not reaped or not ptys_terminated or appdata.exists() or home.exists():
            report.update({"status": "failed", "cleanupFailed": True})
    finally:
        # Cleanup faults must never discard the run's primary result.
        atomic(root / "result.json", report)


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkout", type=Path, default=REPO / "artifacts/e0-desktop-checkout")
    parser.add_argument("--target", type=Path, default=REPO / "artifacts/e0-desktop-build-target")
    parser.add_argument("--run", action="store_true", help="Build and launch the isolated native fixture")
    args = parser.parse_args()
    checkout = args.checkout.resolve()
    assert checkout != Path("/Users/woro/Documents/Lomi/lomi")
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip() == AUDIT
    build_receipt.exact_checkout(REPO, checkout)
    dependency_root = (checkout / "node_modules").resolve()
    assert digest(checkout / "pnpm-lock.yaml") == digest(dependency_root / ".pnpm/lock.yaml")
    node = Path(shutil.which("node")).resolve()
    cargo = Path(shutil.which("cargo")).absolute()
    vite = dependency_root / "vite/bin/vite.js"
    assert vite.is_file()
    assert not list(checkout.glob(".env"))
    assert not [p for p in checkout.glob(".env.*") if p.name != ".env.example"]
    report = {"kind": "desktop_e0_native", "auditRevision": AUDIT,
              "platform": platform.platform(), "status": "prepared", "checks": [],
              "dependencies": {"method": "verified read-only node_modules symlinks and explicit CLI paths; pnpm not invoked",
                               "lockSha256": digest(checkout / "pnpm-lock.yaml"),
                               "viteSha256": digest(vite), "nodeSha256": digest(node),
                               "requestedPackageManager":json.loads((checkout / "package.json").read_text())["packageManager"],
                               "installedMetadataSha256":digest(dependency_root / ".modules.yaml")},
              "versions":{name:subprocess.check_output([str(executable),"--version"],text=True).strip() for name,executable in [("node",node),("cargo",cargo),("rustc",cargo.parent / "rustc")]}}
    if not args.run:
        print(json.dumps(report, indent=2))
        return
    assert platform.system() == "Darwin" and platform.machine() == "arm64"
    target = args.target.resolve()
    assert target.parent == REPO / "artifacts" and target.name.startswith("e0-desktop-")
    assert not args.target.is_symlink()
    assert shutil.disk_usage(REPO).free >= 8 * 1024**3, "Controlled native build requires 8 GiB free"
    artifact = REPO / "artifacts/desktop-e0"
    artifact.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="run-", dir=artifact)).resolve()
    root.chmod(0o700)
    identifier = "dev.lomi.e0-" + uuid.uuid4().hex
    home = root / "home"
    home.mkdir(mode=0o700)
    appdata = home / "Library/Application Support" / identifier
    appdata.parent.mkdir(parents=True, mode=0o700)
    appdata.mkdir(mode=0o700)  # Exclusive creation; never reuse user app data.
    project = root / "project"
    project.mkdir(mode=0o700)
    disk = project / "private.txt"
    disk.write_text("fixture disk baseline\n")
    disk.chmod(0o600)
    disk_hash = digest(disk)
    atomic(appdata / "session.json", {"version": 5,"projects":[],"activeProjectId":None,"sidebar":"files","sidebarWidth":250,"rightSidebar":None,"rightSidebarWidth":250,"sidebarSides":{"files":"left","git":"right","workspaces":"left"},"terminalOverviewSide":"left"})
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
    config = {"identifier": identifier, "build": {"devUrl": f"http://127.0.0.1:{port}/?e0=main"}}
    env = {"PATH": f"{node.parent}:{cargo.parent}:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(Path.home()),
           "LANG":"en_US.UTF-8", "TMPDIR":str(root), "CARGO_TARGET_DIR":str(target),
           "TAURI_CONFIG":json.dumps(config), "LOMI_AUTH_ORIGIN":"http://127.0.0.1:9", "LOMI_REMOTE_ORIGIN":"http://127.0.0.1:9"}
    report.update({"identifier":identifier,"artifactDirectory":str(root),"appdata":str(appdata)})
    native = vite_process = host = None
    log = None
    sequence = 0
    fixture_pids = []
    def command(op, **data):
        nonlocal sequence
        sequence += 1
        atomic(root / "command.json", {"seq":sequence,"op":op,**data})
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if native.poll() is not None:
                raise RuntimeError("Native fixture exited before receipt")
            try:
                receipt = json.loads((root / "reply.json").read_text())
            except (OSError, ValueError):
                receipt = {}
            if receipt.get("seq") == sequence:
                assert receipt["ok"], receipt.get("error")
                return receipt["result"]
            time.sleep(.1)
        raise RuntimeError("Native fixture receipt deadline")
    def renderer(op, view="main", **data):
        result = command("eval", view=view, command={"op":op, **data})
        assert result["ok"], {"rendererOperationFailed":op}
        return result["result"]
    def domain(op, **data):
        host.stdin.write(json.dumps({"op":op, **data}) + "\n")
        host.stdin.flush()
        ready = selectors.DefaultSelector()
        ready.register(host.stdout, selectors.EVENT_READ)
        try:
            assert ready.select(timeout=5), "Domain fixture deadline"
            result = json.loads(host.stdout.readline(16385))
            return result
        finally:
            ready.close()
    def retained(before, after):
        for key in ["documentId","privateId","textHash","selection","undo","redo","bufferRevision","diskRevision","dirty"]:
            assert before[key] == after[key], key
        assert after["dirty"] and after["editorMounted"] and after["undo"] > 0
    try:
        inputs = build_receipt.snapshot(REPO, checkout, target, env)
        receipt_path = root / "build-receipt.json"
        with (root / "build.log").open("wb") as build_log:
            for cmd, cwd in [([str(cargo), "build", "--manifest-path", "tests/desktop-e0/host/Cargo.toml", "--locked", "--offline"], REPO),
                             ([str(node), str(dependency_root / "typescript/bin/tsc"), "--noEmit"], checkout),
                             ([str(cargo), "build", "--manifest-path", "src-tauri/Cargo.toml", "--locked", "--offline", "--features", "e0-desktop-probe"], checkout)]:
                result = run_owned(cmd, cwd=cwd, env=env, timeout=1200)
                build_log.write((result.stdout + result.stderr).encode())
                report["checks"].append({"command":cmd,"exitCode":result.returncode})
                assert result.returncode == 0, "Build failed; see private build.log"
        after_inputs = build_receipt.snapshot(REPO, checkout, target, env)
        assert inputs == after_inputs, "Controlled build inputs changed during compilation"
        private_binary = root / "lomi-e0"
        shutil.copy2(Path(env["CARGO_TARGET_DIR"]) / "debug/lomi", private_binary)
        private_binary.chmod(0o700)
        private_host = root / "lomi-e0-host"
        shutil.copy2(target / "debug/lomi-e0-desktop-host-fixture", private_host)
        private_host.chmod(0o700)
        binaries = {"desktop": private_binary, "domain": private_host}
        atomic(receipt_path, build_receipt.receipt(inputs, binaries, report["checks"]))
        build_receipt.verify(receipt_path, build_receipt.snapshot(REPO, checkout, target, env), binaries, report["checks"])
        report["buildReceiptSha256"] = digest(receipt_path)
        report["binarySha256"] = digest(private_binary)
        report["domainBinarySha256"] = digest(private_host)
        vite_config = root / "vite.e0.config.mjs"
        vite_config.write_text(f'import base from {json.dumps(str(checkout / "vite.config.ts"))}; export default {{...base,envDir:false,cacheDir:{json.dumps(str(root / "vite-cache"))},server:{{...base.server,port:{port}}}}};')
        log = (root / "fixture.log").open("wb")
        vite_process = subprocess.Popen([str(node),str(vite),"--config",str(vite_config)],cwd=checkout,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        import urllib.request
        for _ in range(200):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}",timeout=1) as response:
                    if response.status == 200: break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError("Vite fixture deadline")
        # Drop all inherited account/network/credential/configuration variables.
        runtime_env = {"PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "HOME":str(home),"ZDOTDIR":str(home),"LANG":"en_US.UTF-8","TMPDIR":str(root),
                       "LOMI_E0_DIRECTORY":str(root),"LOMI_E0_APPDATA":str(appdata),"LOMI_AUTH_ORIGIN":"http://127.0.0.1:9","LOMI_REMOTE_ORIGIN":"http://127.0.0.1:9"}
        # A separate native negative run must terminate itself with watchdog code
        # 2. A runner SIGTERM must never masquerade as watchdog success.
        watchdog = subprocess.Popen([str(private_binary)], cwd=project,
            env={**runtime_env, "LOMI_E0_WATCHDOG_TICKS": "2"},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            watchdog_exit = watchdog.wait(timeout=20)
            report["watchdogNegativeControl"] = {"exitCode": watchdog_exit, "shortenedTicks": 2}
            assert watchdog_exit == 2, "Native watchdog did not exit with code 2"
        finally:
            stop(watchdog)
        native = subprocess.Popen([str(private_binary)],cwd=project,env=runtime_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        time.sleep(4)
        report["initialRenderer"] = command("diagnostic")
        init = renderer("initialize", root=str(project))
        host = subprocess.Popen([str(private_host)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,env=runtime_env,start_new_session=True)
        snapshot = domain("init",**{k:init[k] for k in ["tabA","tabB","paneA","paneB","paneC"]})
        assert snapshot["ok"]
        baseline = renderer("edit")
        assert baseline["dirty"] and baseline["textHash"] != disk_hash
        counts = command("count")
        fixture_pids = counts["pids"]
        assert counts["nativePtys"] >= 1
        snapshot = domain("attach",view="main",pane=init["paneA"])
        snapshot = domain("attach",view="observer",pane=init["paneA"])
        assert snapshot["attachments"] == 2
        atomic(root / "snapshot.json",snapshot)
        created = command("observer")
        time.sleep(2)
        observed = renderer("projection",view="e0-observer")
        assert observed == snapshot
        assert renderer("production-denied",view="e0-observer") is True
        assert command("count") == counts
        assert counts["nativePtys"] == created["nativePtys"]
        retained(baseline,renderer("inspect"))
        report["observerAttach"]={"attachments":2,"sameHostSnapshot":True,"nativePtyCountBefore":counts["nativePtys"],"nativePtyCountAfter":created["nativePtys"]}
        moved = domain("move",pane=init["paneA"],tab=init["tabB"],expected=1)
        assert moved["ok"] and moved["revision"]==2
        ignored = command("eval", view="main", command={"op":"apply", "snapshot":moved, "noopSetter":True})
        assert ignored["ok"] is False, "Ignored Workbench setter was falsely accepted"
        report["ignoredSetterNegativeControl"] = {"rejected": True}
        retained(baseline,renderer("apply",snapshot=moved))
        stale = domain("close",pane=init["paneA"],expected=1)
        assert not stale["ok"] and stale["error"]=="RevisionConflict" and stale["revision"]==2
        retained(baseline,renderer("inspect"))
        closed = domain("close",pane=init["paneC"],expected=2)
        assert closed["ok"] and closed["revision"]==3
        after = renderer("apply",snapshot=closed)
        retained(baseline,after)
        assert after["privateIds"] == [baseline["privateId"]]
        assert init["paneC"] not in after["terminalIds"]
        assert init["paneA"] in after["terminalIds"]
        history = renderer("history")
        # Undo/redo intentionally advance the buffer revision and restore the
        # edit's history selection. Layout operations above retain both exactly.
        retained({**baseline,"bufferRevision":history["redone"]["bufferRevision"],"selection":history["redone"]["selection"]},history["redone"])
        assert history["undone"]["textHash"] != baseline["textHash"]
        assert digest(disk)==disk_hash
        atomic(root / "snapshot.json",closed)
        assert renderer("projection",view="e0-observer")==closed
        report["screenshots"] = {label:command("screenshot",view=label) for label in ["main","e0-observer"]}
        report.update({"status":"passed","dirtyRetention":{k:after[k] for k in ["documentId","privateId","textHash","bufferRevision","diskRevision","dirty","selection","undo"]},"hostRevisions":[1,2,3],"staleCasRejected":True,"undoRedoVerified":True,"diskUnchanged":True})
    except Exception as error:
        report.update({"status":"failed","error":str(error)})
    finally:
        # Rendering another committed tab may initialize a previously hidden
        # native PTY. Bind every currently owned PID before native shutdown too.
        if native and native.poll() is None:
            try:
                fixture_pids = sorted(set(fixture_pids + command("count")["pids"]))
            except Exception as error:
                report.update({"status": "failed", "ptyInventoryError": type(error).__name__})
        cleanup_fixture(report, root, appdata, home, [host, native, vite_process], fixture_pids,
                        log, lambda: command("exit"))
    print(json.dumps(report,indent=2))
    assert report["status"]=="passed", "Native E0 fixture failed"

if __name__ == "__main__":
    main()
