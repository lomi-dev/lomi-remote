#!/usr/bin/env python3
"""Transfer approved source and run only synthetic Git probes in disposable lomi-e0."""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import time
import uuid
from owned_process import initialize_process_ownership, run_owned
from source_manifest import source_inventory

ROOT=Path(__file__).resolve().parents[1]
ARTIFACTS=ROOT/"artifacts/git-linux"
LIMA="/opt/homebrew/bin/limactl"
VM="lomi-e0"
ENV={"HOME":str(Path.home()),"PATH":"/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
     "LIMA_HOME":str(ROOT/"artifacts/lima"),"LC_ALL":"C","TERM":"dumb"}

def main():
    initialize_process_ownership()
    if sys.platform!="darwin" or not Path(ENV["LIMA_HOME"]).is_dir():
        raise SystemExit("requires the existing disposable native ARM64 lomi-e0 VM")
    ARTIFACTS.mkdir(parents=True,exist_ok=True)
    for name in ["build-native-crate.log","lint-native-crate.log","native-adversarial-regressions.log"]:
        (ARTIFACTS/name).unlink(missing_ok=True)
    guest="/home/lomi-e0/lomi-git-source/run-"+uuid.uuid4().hex
    report={"kind":"native-linux-git-feasibility","qualified":False,"complete":False,
            "generatedAt":datetime.now(timezone.utc).isoformat(),"environment":{"host":platform.platform()},
            "guestSource":guest,"operations":[],"not_run":["hardlink/live-tree secrecy","outside metadata secrecy","production qualification"]}
    def save(): (ARTIFACTS/"evidence.json").write_text(json.dumps(report,indent=2)+"\n")
    def invoke(name,argv,timeout=120):
        step={"name":name,"argv":argv,"timeoutSeconds":timeout,"exitCode":None,"status":"running"}
        report["operations"].append(step);save();started=time.monotonic()
        try:
            result=run_owned(argv,cwd=ROOT,env=ENV,timeout=timeout)
            step.update({"exitCode":result.returncode,"status":"passed" if result.returncode==0 else "failed"})
            if result.returncode:
                # Compiler diagnostics concern only the approved synthetic source.
                if name in {"build-native-crate","lint-native-crate","native-adversarial-regressions"}:
                    (ARTIFACTS/(name+".log")).write_text(result.stderr)
                raise RuntimeError(name)
            return result.stdout
        except BaseException as error:
            step["errorClass"]=type(error).__name__;raise
        finally: step["durationSeconds"]=round(time.monotonic()-started,3);save()
    def shell(name,argv,timeout=120):
        return invoke(name,[LIMA,"shell","--workdir=/",VM,"--",*argv],timeout)
    try:
        inventory=source_inventory(ROOT)
        selected={p:h for p,h in inventory["files"].items() if p in {"Cargo.toml","Cargo.lock","rust-toolchain.toml"} or p.startswith(("crates/","vendor/","tests/git-linux/"))}
        archive=ARTIFACTS/"approved-source.tar.gz"
        with tarfile.open(archive,"w:gz") as tar:
            for relative,digest in selected.items():
                data=(ROOT/relative).read_bytes()
                if hashlib.sha256(data).hexdigest()!=digest: raise RuntimeError("source changed during transfer")
                entry=tarfile.TarInfo(relative);entry.size=len(data);entry.mode=0o644;tar.addfile(entry,io.BytesIO(data))
        encoded=json.dumps(selected,sort_keys=True,separators=(",",":")).encode()
        report["source"]={"sha256":hashlib.sha256(encoded).hexdigest(),"fileCount":len(selected),"files":selected}
        metadata=shell("native-environment",["python3","-c","import json,platform,os,subprocess; print(json.dumps({'os':platform.platform(),'distribution':platform.freedesktop_os_release().get('PRETTY_NAME'),'arch':platform.machine(),'uid':os.getuid(),'git':subprocess.check_output(['/usr/bin/git','--version'],text=True).strip(),'rustc':subprocess.check_output(['/home/lomi-e0/.cargo/bin/rustc','--version'],text=True).strip()}))"])
        report["environment"]["guest"]=json.loads(metadata)
        assert report["environment"]["guest"]["uid"]!=0 and report["environment"]["guest"]["arch"]=="aarch64"
        remote_archive="/home/lomi-e0/lomi-git-source/approved-"+uuid.uuid4().hex+".tar.gz"
        shell("create-new-synthetic-source-root",["mkdir","-p","/home/lomi-e0/lomi-git-source"])
        invoke("copy-approved-archive",[LIMA,"copy",str(archive),VM+":"+remote_archive])
        extract="import pathlib,tarfile; p=pathlib.Path("+repr(guest)+"); p.mkdir(); t=tarfile.open("+repr(remote_archive)+"); assert all(m.isfile() and not pathlib.PurePosixPath(m.name).is_absolute() and '..' not in pathlib.PurePosixPath(m.name).parts for m in t.getmembers()); t.extractall(p,filter='data')"
        shell("extract-fresh-approved-source",["python3","-c",extract])
        shell("create-owned-build-cache",["mkdir","-p",guest+"/cargo-home",guest+"/tmp"])
        shell("compile-pinned-header-assertions",["env","TMPDIR="+guest+"/tmp","cc","-Wall","-Wextra","-Werror",guest+"/tests/git-linux/headers.c","-o",guest+"/header-probe"])
        shell("run-unprivileged-header-assertions",[guest+"/header-probe"])
        cargo=["env","CARGO_HOME="+guest+"/cargo-home","TMPDIR="+guest+"/tmp","/home/lomi-e0/.cargo/bin/cargo"]
        shell("build-native-crate",[*cargo,"build","--locked","--manifest-path",guest+"/Cargo.toml","-p","lomi-linux-git-spike"],600)
        shell("lint-native-crate",[*cargo,"clippy","--locked","--manifest-path",guest+"/Cargo.toml","-p","lomi-linux-git-spike","--","-D","warnings"],600)
        binary=guest+"/target/debug/lomi-linux-git-spike"
        result=json.loads(shell("native-adversarial-regressions",[binary,"regression"],120))
        assert result["qualified"] is False and result["checksPassed"]>0
        review_code="import subprocess; p=subprocess.run(["+repr(binary)+",'review-regressions'],capture_output=True,text=True,timeout=10); assert p.returncode==0,p.stderr; print(p.stdout,end='')"
        report["reviewRegressions"]=json.loads(shell("bounded-review-regressions",["python3","-c",review_code],20))
        assert report["reviewRegressions"]["qualified"] is False and report["reviewRegressions"]["reviewChecksPassed"]==2
        cancel_code = """import json,os,signal,subprocess,time,pathlib
for sig in [signal.SIGINT,signal.SIGKILL]:
 p=subprocess.Popen([BINARY,'cancel'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 try:
  assert p.stdout.readline().strip()=='synthetic-cancellation-ready'
  line=p.stdout.readline().strip(); assert line.startswith('worker-ready:'); group=int(line.split(':')[1])
  deadline=time.monotonic()+5
  while True:
   children=pathlib.Path('/proc/'+str(group)+'/task/'+str(group)+'/children').read_text().split()
   if any(os.readlink('/proc/'+pid+'/exe')=='/usr/bin/git' for pid in children): break
   assert time.monotonic()<deadline,'Git image not reached before signal'
   time.sleep(.01)
  p.send_signal(sig); out,err=p.communicate(timeout=10)
  if sig==signal.SIGINT: assert p.returncode==0 and json.loads(out)['cancellationPassed'] is True
  else: assert p.returncode==-signal.SIGKILL
  deadline=time.monotonic()+5
  while True:
   try: os.killpg(group,0)
   except ProcessLookupError: break
   assert time.monotonic()<deadline,'owned group survived owner loss'
   time.sleep(.01)
 finally:
  if p.poll() is None: p.kill();p.wait()
print(json.dumps({'qualified':False,'interruptCleanup':True,'forcedOwnerLossCleanup':True,'gitImageObservedBeforeSignals':True}))
""".replace('BINARY',repr(binary))
        report["lifecycle"]=json.loads(shell("interrupt-and-forced-owner-loss-cleanup",["python3","-c",cancel_code],30))
        report["regressions"]=result;report["complete"]=True
        print(json.dumps({"qualified":False,"checksPassed":result["checksPassed"],"reviewChecksPassed":report["reviewRegressions"]["reviewChecksPassed"],"knownLimitsObserved":result["knownLimitsObserved"]}))
        return 0
    except BaseException as error:
        report["errorClass"]=type(error).__name__
        print("Linux Git probe incomplete: "+type(error).__name__,file=sys.stderr)
        return 130 if isinstance(error,KeyboardInterrupt) else 1
    finally: save()

if __name__=="__main__": raise SystemExit(main())
