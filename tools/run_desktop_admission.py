#!/usr/bin/env python3
"""Private macOS E0 native guard/real editor-command admission probe.
Does not qualify execution::run, authenticated MCP policy, or a product host.
"""
import argparse, hashlib, json, os, pathlib, shutil, socket, struct, subprocess, sys, tempfile, time, uuid
from owned_process import initialize_process_ownership, run_owned, stop_group
ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/desktop-admission"
CHECKOUT = ROOT / "artifacts/e0-admission-checkout"
TARGET = ROOT / "artifacts/e0-admission-target"
EVIDENCE = ROOT / "artifacts/desktop-admission.json"
sys.path.insert(0, str(SOURCE))
import build_receipt
from cleanup import finish as finish_cleanup, require_clean_exit
RECEIPT = ROOT / "artifacts/desktop-admission-build-receipt.json"
BINARIES = {name: ROOT / "artifacts/e0-admission-build" / name for name in ["host", "desktop", "controlled-child"]}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--dev-server-sentinel", action="store_true", help="prove private page ignores an owned unapproved server on port 1420")
    parser.add_argument("--lose-native-reply", action="store_true", help="negative proof of uncertain spawn delivery")
    parser.add_argument("--exit-wrapper-73", action="store_true", help="negative lifecycle proof with the actual desktop")
    args = parser.parse_args()
    evidence = EVIDENCE
    if args.exit_wrapper_73: evidence=EVIDENCE.with_name("desktop-admission-exit73.json")
    if args.dev_server_sentinel: evidence=EVIDENCE.with_name("desktop-admission-devserver.json")
    if args.lose_native_reply: evidence=EVIDENCE.with_name("desktop-admission-lostreply.json")
    report = {"passed": False, "cleanupCompleted": False, "checks": [], "qualification": "actual native guard and save_editor_file; isolated Tauri AppHandle", "notQualified": ["execution::run task/account/attempt dispatch", "managed/unscoped SessionRequestPolicy authentication and owner validation", "production Desktop/host integration", "Linux/Windows"]}
    evidence.parent.mkdir(exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2) + "\n")
    processes = []
    directory = None
    appdata = None
    native_alive = False
    app = None
    sequence = 0
    sockets = []
    def check(name, condition):
        if not condition: raise AssertionError(name)
        report["checks"].append(name)
    def stop(process):
        # Already reaped processes cannot safely identify a process group.
        if process.returncode is None:
            stop_group(process)
    def rpc(op, **values):
        nonlocal sequence
        request = directory / f"request-{sequence}.json"
        reply = directory / f"reply-{sequence}.json"
        temporary = request.with_suffix(".tmp")
        temporary.write_text(json.dumps({"op": op, **values}))
        temporary.rename(request)
        sequence += 1
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            if reply.exists():
                try:
                    value=json.loads(reply.read_text())
                    if op == "native" and args.lose_native_reply:
                        raise TimeoutError("injected lost native spawn reply")
                    return value
                except json.JSONDecodeError: pass
            time.sleep(.02)
        raise TimeoutError("native probe deadline")
    def host_start():
        process = subprocess.Popen([str(directory / "host"), "host", str(directory / "ipc")], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        processes.append(process)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.socket(socket.AF_UNIX) as stream:
                    stream.settimeout(.1); stream.connect(str(directory / "ipc/host.sock"))
                return process
            except OSError: time.sleep(.02)
        raise TimeoutError("host startup deadline")
    def request(value, retain=False):
        deadline = time.monotonic() + 2
        stream = socket.socket(socket.AF_UNIX)
        sockets.append(stream)
        try:
            stream.settimeout(max(.001, deadline-time.monotonic()))
            stream.connect(str(directory / "ipc/host.sock"))
            payload = json.dumps(value).encode()
            stream.sendall(struct.pack("!I",len(payload))+payload)
            def receive(size):
                result=b""
                while len(result)<size:
                    stream.settimeout(max(.001, deadline-time.monotonic()))
                    block=stream.recv(size-len(result))
                    if not block: raise RuntimeError("IPC closed")
                    result+=block
                return result
            size=struct.unpack("!I",receive(4))[0]
            if not 0<size<=16384: raise RuntimeError("IPC frame limit")
            reply=json.loads(receive(size))
            if retain:
                return reply, stream
            if reply["ok"] and reply.get("token"):
                payload=json.dumps({"op":"Finish","token":reply["token"]}).encode()
                stream.sendall(struct.pack("!I",len(payload))+payload)
                receive(struct.unpack("!I",receive(4))[0])
            return reply
        finally:
            if not retain: stream.close()
    try:
        if os.uname().sysname != "Darwin": raise RuntimeError("requires actual macOS Tauri")
        manifest=json.loads((SOURCE/"source-manifest.json").read_text())
        if args.skip_build and not RECEIPT.is_file():
            raise RuntimeError("verified E0 build receipt required before skip-build")
        report["sourceManifestSha256"]=digest(SOURCE/"source-manifest.json")
        report["sourceDigests"]={str(path.relative_to(ROOT)):digest(path) for path in [SOURCE/"bridge.rs",SOURCE/"support.rs",SOURCE/"controlled-child.rs",ROOT/"crates/lomi-admission-spike/src/client.rs",ROOT/"crates/lomi-admission-spike/src/lib.rs",ROOT/"crates/lomi-admission-spike/Cargo.toml",pathlib.Path(__file__).resolve()]}
        main_checkout=ROOT.parent/"lomi"
        for name in ["package.json","pnpm-lock.yaml"]:
            check("verified installed dependency source "+name,digest(main_checkout/name)==digest(CHECKOUT/name))
        check("detached baseline", build_receipt.command(["git","-C",str(CHECKOUT),"rev-parse","HEAD"],timeout=10)==manifest["revision"])
        for name, expected in manifest["patchedSha256"].items(): check("source "+name, digest(CHECKOUT/name)==expected)
        if not args.skip_build:
            if shutil.disk_usage(ROOT).free < 8*1024**3: raise RuntimeError("private build requires 8 GiB free")
            build_receipt.build(ROOT, SOURCE, CHECKOUT, TARGET, RECEIPT, BINARIES)
        inputs = build_receipt.snapshot(ROOT, SOURCE, CHECKOUT, TARGET)
        receipt = build_receipt.verify(RECEIPT, inputs, BINARIES)
        report["buildReceiptSha256"] = digest(RECEIPT)
        report["verifiedBuildInputsSha256"] = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
        directory=pathlib.Path(tempfile.mkdtemp(prefix="lomi-e0-admission-",dir="/private/tmp")).resolve()
        identifier="dev.lomi.e0-admission-"+uuid.uuid4().hex
        candidate=pathlib.Path.home()/"Library/Application Support"/identifier
        candidate.mkdir(mode=0o700)
        appdata=candidate
        for name in ["project","child-home","home"]: (directory/name).mkdir(mode=0o700)
        (directory/"project/file.txt").write_text("before\n")
        for name, binary in BINARIES.items():
            shutil.copy2(binary, directory/name)
        if {name:digest(directory/name) for name in BINARIES} != receipt["binaries"]:
            raise RuntimeError("private binary copy differs from verified receipt")
        report["binaries"]={name:digest(directory/name) for name in ["host","desktop","controlled-child"]}
        report["versions"]=inputs["toolchain"]
        environment={"PATH":"/usr/bin:/bin","HOME":str(directory/"home"),"TMPDIR":str(directory),"LANG":"en_US.UTF-8"}
        if args.dev_server_sentinel:
            sentinel=subprocess.Popen([sys.executable,str(SOURCE/"dev_server_sentinel.py"),str(directory)],env=environment,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
            processes.append(sentinel)
            deadline=time.monotonic()+5
            while not (directory/"dev-server-ready").exists():
                if time.monotonic()>=deadline: raise TimeoutError("owned port1420 sentinel startup failed; existing listeners are not altered")
                time.sleep(.02)
        host=host_start()
        launch=[str(directory/"desktop")]
        if args.exit_wrapper_73:
            launch=[sys.executable, str(SOURCE/"exit_wrapper.py"), *launch]
        app=subprocess.Popen(launch,env={**environment,"LOMI_E0_IDENTIFIER":identifier,"LOMI_E0_PROBE_DIRECTORY":str(directory),"LOMI_E0_ADMISSION_DIRECTORY":str(directory/"ipc")},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        processes.append(app)
        page=rpc("page")
        check("real native window has no frontend webview",page.get("ok") and page.get("value",{}).get("frontend")=="none")
        save={"root":str(directory/"project"),"relative":"file.txt","content":"after\n","revision":hashlib.sha256(b"before\n").hexdigest()}
        held, held_stream=request({"op":"Acquire","path":str(directory/"project"),"kind":"native"},retain=True)
        check("external host native held",held["ok"])
        check("IPC native blocks actual editor command",not rpc("save",request=save)["ok"])
        # This external fixture represents no child and completes synchronously.
        payload=json.dumps({"op":"Finish","token":held["token"]}).encode()
        held_stream.settimeout(2)
        held_stream.sendall(struct.pack("!I",len(payload))+payload)
        held_stream.recv(16388); held_stream.close()
        check("real editor save completes",rpc("save",request=save)["ok"])
        check("actual disk save",(directory/"project/file.txt").read_text()=="after\n")
        # Delivery or a missing reply cannot prove that no child was spawned.
        native_alive=True
        native=rpc("native"); check("actual guard native activation",native["ok"])
        token=native["value"]["token"]
        check("actual Lease::check renews",rpc("check")["ok"])
        check("managed branch native lease check renews",rpc("managed_check")["ok"])
        save["revision"]=hashlib.sha256(b"after\n").hexdigest();save["content"]="forbidden\n"
        check("actual save_editor_file blocked by native",not rpc("save",request=save)["ok"])
        check("native blocks opaque MCP guard",not rpc("unscoped")["ok"])
        check("host native blocks opaque admission",not request({"op":"AcquireUnscoped"})["ok"])
        for kind in ["file","git"]:
            check("native blocks remote "+kind,not request({"op":"Acquire","path":str(directory/"project"),"kind":kind})["ok"])
        stop(host)
        check("IPC loss rejects actual Lease::check",not rpc("check")["ok"])
        check("IPC loss rejects managed native lease check",not rpc("managed_check")["ok"])
        host=host_start()
        check("native drop disconnects while owned child alive",rpc("drop")["ok"])
        time.sleep(.15)
        for kind in ["file","git"]:
            check("disconnect quarantine blocks "+kind,not request({"op":"Acquire","path":str(directory/"project"),"kind":kind})["ok"])
        stop(host); host=host_start()
        time.sleep(2.2)
        for kind in ["file","git"]:
            check("restart and expiry preserve quarantine "+kind,not request({"op":"Acquire","path":str(directory/"project"),"kind":kind})["ok"])
        check("termination assertion false denied",not request({"op":"Reconcile","token":token,"confirmed_terminated":False})["ok"])
        waited=rpc("terminate_wait");check("owned native child killed and waited",waited["ok"] and waited["value"]["waited"])
        native_alive=False
        check("explicit reconcile after wait",request({"op":"Reconcile","token":token,"confirmed_terminated":True})["ok"])
        for kind in ["file","git"]:
            check("reconciled acquisition succeeds "+kind,request({"op":"Acquire","path":str(directory/"project"),"kind":kind})["ok"])
        check("real editor save after reconcile",rpc("save",request=save)["ok"])
        check("opaque guard completes",rpc("unscoped")["ok"])
        native_alive=True
        check("native startup after completed writes",rpc("native")["ok"])
        check("owned final child killed and waited",rpc("terminate_wait")["ok"])
        native_alive=False
        rpc("exit")
        require_clean_exit(app, report)
        if args.dev_server_sentinel:
            report["unapprovedDevServerRequests"]=json.loads((directory/"dev-server-requests.json").read_text())
            check("private page makes zero requests to unapproved port1420",report["unapprovedDevServerRequests"]==0)
        report["passed"]=True
    except BaseException as error:
        report["error"]=type(error).__name__ + ": " + str(error)
        report["passed"]=False
    finally:
        try:
            def settle_owned_child():
                nonlocal native_alive
                if native_alive:
                    result=rpc("terminate_wait")
                    native_alive=not (result["ok"] and result["value"]["waited"])
                    if native_alive: raise RuntimeError("owned child settlement unproved")
                    report["ownedNativeChildWaitedDuringCleanup"]=True
            def remove_private(path):
                result=run_owned([sys.executable, "-c", "import shutil,sys; shutil.rmtree(sys.argv[1])", str(path)], timeout=10)
                result.check_returncode()
            def stop_owned(process):
                if process is app and process.returncode is None:
                    report["desktopExit"]={"code":None,"signal":None,"forcedCleanup":True}
                stop(process)
                if process is app and report.get("desktopExit",{}).get("forcedCleanup"):
                    code=process.returncode
                    report["desktopExit"].update({"code":code if code is not None and code >= 0 else None,"signal":-code if code is not None and code < 0 else None})
            steps=[("owned native child kill/wait", settle_owned_child)]
            steps += [("socket close", stream.close) for stream in sockets]
            steps += [("owned process group stop/wait", lambda process=process: stop_owned(process)) for process in reversed(processes)]
            if directory is not None: steps.append(("private fixture removal", lambda: remove_private(directory)))
            if appdata is not None: steps.append(("private appdata removal", lambda: remove_private(appdata)))
            finish_cleanup(report, steps, evidence)
        except BaseException as error:
            report["passed"]=False
            report["cleanupCompleted"]=False
            report.setdefault("cleanupErrors", []).append({"step":"cleanup coordinator","error":type(error).__name__})
        finally:
            evidence.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"passed":report["passed"],"checks":len(report["checks"]),"cleanupCompleted":report["cleanupCompleted"],"error":report.get("error")}))
    return 0 if report["passed"] else 1
if __name__=="__main__": raise SystemExit(main())
