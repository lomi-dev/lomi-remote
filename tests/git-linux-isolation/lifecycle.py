"""Synthetic owner-loss and private namespace/capability assertions."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

def children(pid):
    return [int(p) for p in Path(f"/proc/{pid}/task/{pid}/children").read_text().split()]

def main():
    binary = sys.argv[1]
    checked = []
    for sig in (signal.SIGINT, signal.SIGKILL):
        child = subprocess.Popen([binary, "cancel"], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"})
        group = None
        try:
            line = child.stdout.readline().strip()
            assert line.startswith("worker-ready:")
            group = int(line.split(":")[1])
            deadline = time.monotonic() + 4
            while True:
                branch = children(group)
                if branch and children(branch[0]):
                    broker, bootstrap = branch[0], children(branch[0])[0]
                    break
                assert time.monotonic() < deadline
                time.sleep(.01)
            for pid in (broker, bootstrap):
                for ns in ("user", "mnt", "pid", "net"):
                    assert os.readlink(f"/proc/{pid}/ns/{ns}") != os.readlink(f"/proc/self/ns/{ns}")
                status = dict(line.split(":",1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
                for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    assert int(status[field].strip(), 16) == 0
                assert status["NoNewPrivs"].strip() == "1"
            child.send_signal(sig)
            out, err = child.communicate(timeout=10)
            if sig == signal.SIGINT:
                assert child.returncode == 0 and json.loads(out)["cancellationPassed"]
            else:
                assert child.returncode == -signal.SIGKILL
            deadline = time.monotonic() + 5
            while True:
                try:
                    os.killpg(group, 0)
                except ProcessLookupError:
                    break
                assert time.monotonic() < deadline, "owned namespace group survived"
                time.sleep(.01)
            checked.append(sig.name)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)
    print(json.dumps({"qualified": False, "ownerLossChecks": checked,
        "privateUserMountPidNetNamespaces": True, "allCapabilitySetsZero": True,
        "noNewPrivsBeforeFork": True}))

if __name__ == "__main__":
    main()
