#!/usr/bin/env python3
"""Isolated synthetic native proof. Stdout is a boolean/count/hash receipt only.

No relay authority claim is made: the caller must independently enforce actual
current relay authority after a channel's admission deadline.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import re
import signal
import select
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("owned_process", ROOT / "tools/owned_process.py")
owned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cbor(value):
    """Canonical test input encoding only; signatures/verification stay in Rust."""
    def head(major, n):
        if n < 24:
            return bytes([major * 32 + n])
        for width, marker in [(1, 24), (2, 25), (4, 26), (8, 27)]:
            if n < 1 << (width * 8):
                return bytes([major * 32 + marker]) + n.to_bytes(width, "big")
        raise RuntimeError("bounded input")
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("ascii")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(map(cbor, value))
    raise RuntimeError("bounded input")


class Peer:
    def __init__(self, binary, home):
        self.child = subprocess.Popen(
            [str(binary)], cwd=home,
            env={"HOME": home, "TMPDIR": home, "PATH": "/usr/bin:/bin", "LANG": "C"},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            # Stay inside the outer owned group so timeout SIGTERM reaches us both.
            start_new_session=False,
        )
        self.count = 0

    def call(self, op, expect=True, **fields):
        self.count += 1
        encoded = json.dumps(dict(op=op, **fields), separators=(",", ":")).encode() + b"\n"
        if len(encoded) > 128 * 1024:
            raise RuntimeError("bounded input")
        self.child.stdin.write(encoded)
        self.child.stdin.flush()
        if not select.select([self.child.stdout], [], [], 5)[0]:
            raise RuntimeError("native response timeout")
        raw = self.child.stdout.readline(128 * 1024 + 1)
        response = json.loads(raw)
        if response.get("ok") is not expect:
            raise RuntimeError("native expectation failed")
        if not expect:
            if response != {"ok": False, "error": "NATIVE_FIXTURE_REJECTED"}:
                raise RuntimeError("native error contract")
            return None
        if set(response) != {"ok", "result"}:
            raise RuntimeError("native response contract")
        return response["result"]

    def close(self):
        # Never poll/reap before owned cleanup; the direct child retains the PID.
        owned.require_unreaped_child(self.child)
        try:
            try:
                os.kill(self.child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            # Retain the unreaped child through the final signal: its PID cannot
            # be reused. Never signal the inherited group (which includes us).
            time.sleep(0.25)
            owned.require_unreaped_child(self.child)
            try:
                os.kill(self.child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        finally:
            self.child.communicate(timeout=2)


def run(binary):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    owned.initialize_process_ownership()
    with tempfile.TemporaryDirectory(prefix="lomi-native-transport-") as home:
        os.chmod(home, 0o700)
        peer = Peer(binary, home)
        try:
            ident = peer.call("init", account_id=[1]*16, host_id=[2]*16, window_id=[3]*16)
            hp, cp = ident["hostPin"], ident["consumerPin"]
            now = int(time.time())
            # Both challenge signers verify their own typed output using canonical APIs.
            enrollment = ["lomi-remote-host-enrollment-proof-v1", 1, bytes([4]*16), bytes([2]*16), bytes(hp), bytes([5]*16), "synthetic.invalid", now+60, bytes([6]*32), bytes([7]*16)]
            window = ["lomi-remote-consumer-window-proof-v1", 1, bytes([1]*16), bytes([8]*16), "synthetic_session", bytes([3]*16), bytes(cp), bytes([9]*16), bytes([10]*32), "synthetic.invalid", now+60]
            peer.call("sign_enrollment", canonical_cbor=list(cbor(enrollment)))
            peer.call("sign_window", canonical_cbor=list(cbor(window)))
            bad_window = copy.deepcopy(window)
            bad_window[5] = bytes([99]*16)
            peer.call("sign_window", expect=False, canonical_cbor=list(cbor(bad_window)))
            grant = dict(version=3, apiMajor=2, applicationMajor=2, accountId=[1]*16, hostId=[2]*16,
                         hostFingerprint=hp, hostAuthorizationId=[4]*16, accessEpoch="1",
                         consumerAuthorizationId=[8]*16, accountSessionId="synthetic_session", consumerId=[3]*16,
                         consumerFingerprint=cp, grantId=[11]*16, grantRevision="1", workspaceId=[12]*16,
                         workspaceEpoch=[13]*16, runtimeId=[14]*16, runtimeGeneration="1",
                         capabilities=["workspace.read"], nonce=[15]*32, expiresAt=str(now+120), purpose="workspace")
            signed_grant = peer.call("sign_grant", grant=grant)
            authority = {k: grant[k] for k in ["hostAuthorizationId", "consumerAuthorizationId", "accountSessionId", "accessEpoch", "grantRevision", "workspaceEpoch", "runtimeId", "runtimeGeneration"]}
            authority["terminalMembership"] = None

            def make_context(channel, seconds):
                start = int(time.time())
                context = dict(version=3, grant=grant, channelId=[channel]*16, initiatorRole="device",
                               responderRole="host", purpose="workspace", terminal=None,
                               issuedAt=str(start), expiresAt=str(start+seconds))
                wire = peer.call("sign_context", context=context)
                args = dict(expected_context_cbor=list(bytes.fromhex(wire["canonicalCbor"])),
                            stored_signed_grant_wire=signed_grant, admission_wire=wire,
                            host_identity_wire=ident["hostIdentityWire"], consumer_identity_wire=ident["consumerIdentityWire"],
                            host_pin=hp, consumer_pin=cp, current_authority=authority)
                return context, args

            def exchange(left, right):
                frame = peer.call("write", slot=left)
                peer.call("read", slot=right, bytes=frame)
                frame = peer.call("write", slot=right)
                peer.call("read", slot=left, bytes=frame)
                frame = peer.call("write", slot=left)
                peer.call("read", slot=right, bytes=frame)

            context, args = make_context(16, 4)
            peer.call("start", slot="consumer", initiator=True, **args)
            peer.call("start", slot="host", initiator=False, **args)
            exchange("consumer", "host")
            peer.call("finish", slot="consumer")
            peer.call("finish", slot="host")
            for left, right in [("consumer", "host"), ("host", "consumer")]:
                payload = list(b"synthetic traffic")
                frame = peer.call("seal", slot=left, bytes=payload)
                if peer.call("open", slot=right, bytes=frame) != payload:
                    raise RuntimeError("synthetic transport mismatch")
            peer.call("start", expect=False, slot="reused-admission", initiator=True, **args)
            _, forged = make_context(20, 4)
            wire = forged["admission_wire"]
            wire["signature"] = ("00" if wire["signature"][:2] != "00" else "01") + wire["signature"][2:]
            peer.call("start", expect=False, slot="forged-signature", initiator=True, **forged)
            _, forged_grant = make_context(21, 4)
            forged_grant["stored_signed_grant_wire"] = copy.deepcopy(signed_grant)
            grant_wire = forged_grant["stored_signed_grant_wire"]
            grant_wire["signature"] = ("00" if grant_wire["signature"][:2] != "00" else "01") + grant_wire["signature"][2:]
            peer.call("start", expect=False, slot="forged-grant", initiator=True, **forged_grant)
            _, wrong = make_context(17, 4)
            wrong["consumer_pin"] = [99]*32
            peer.call("start", expect=False, slot="wrong-pin", initiator=True, **wrong)
            _, stale = make_context(18, 4)
            stale["current_authority"] = dict(authority, grantRevision="2")
            peer.call("start", expect=False, slot="stale-authority", initiator=True, **stale)
            late_context, late = make_context(19, 3)
            peer.call("start", slot="late-consumer", initiator=True, **late)
            peer.call("start", slot="late-host", initiator=False, **late)
            exchange("late-consumer", "late-host")
            # Original signed context remains untouched. Real wall time crosses expiry.
            time.sleep(max(0, int(late_context["expiresAt"]) - time.time()) + 0.15)
            peer.call("finish", expect=False, slot="late-consumer")
            peer.call("finish", expect=False, slot="late-host")
            peer.call("write", expect=False, slot="late-consumer")
            peer.call("start", expect=False, slot="expired-new", initiator=True, **late)
            # Established transports remain usable beyond admission expiry.
            time.sleep(max(0, int(context["expiresAt"]) - time.time()) + 0.05)
            frame = peer.call("seal", slot="consumer", bytes=[42])
            if peer.call("open", slot="host", bytes=frame) != [42]:
                raise RuntimeError("established lifetime mismatch")
            peer.call("dispose", slot="consumer")
            peer.call("seal", expect=False, slot="consumer", bytes=[42])
            peer.call("start", expect=False, slot="consumer", initiator=True, **args)
            peer.call("dispose", slot="host")
            peer.call("start", expect=False, slot="stale-clock", initiator=False, now=now, **args)
            peer.call("shutdown")
            count = peer.count
        finally:
            peer.close()
    return dict(ok=True, commandCount=count, realNoiseBidirectional=True,
                publicBinding=True, typedCanonicalSignatures=True, replayAndDisposal=True,
                actualWallClockLateFinishDenied=True, establishedAfterDeadline=True,
                binarySha256=digest(binary), helperSourceSha256=digest(ROOT / "crates/lomi-remote-crypto/examples/transport_authority.rs"),
                driverSourceSha256=digest(__file__))



def inspector_exited(result):
    """Accept only exact public ps evidence; inspector errors fail closed."""
    if result.stderr != "":
        raise RuntimeError("process inspector stderr")
    if result.returncode == 1 and result.stdout == "":
        return True
    if result.returncode == 0 and re.fullmatch(r"[ \t]*Zs?\+?[ \t]*\n?", result.stdout):
        return True
    raise RuntimeError("unconfirmed process exit")


def inspector_decision_controls():
    controls = [
        (1, "", "", True), (0, "Z\n", "", True),
        (0, " Z+ \n", "", True), (2, "", "", False),
        (1, "", "inspector failed", False), (0, "", "", False),
        (0, "S\n", "", False), (1, "Z\n", "", False),
        (0, "Z\nZ\n", "", False), (0, "Z\nS\n", "", False),
        (0, "Zgarbage\n", "", False), (0, "Z\n", "warning", False),
        (0, "Z\n\n", "", False), (-9, "", "", False),
        (0, "Z++\n", "", False), (0, "Zss\n", "", False),
    ]
    for code, stdout, stderr, expected in controls:
        result = subprocess.CompletedProcess([], code, stdout, stderr)
        try:
            actual = inspector_exited(result)
        except RuntimeError:
            actual = False
        if actual is not expected:
            raise RuntimeError("process inspector decision control failed")
    return len(controls)


def run_timeout_regression():
    """Prove outer timeout kills both processes without depending on EOF."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    owned.initialize_process_ownership()
    control_count = inspector_decision_controls()
    with tempfile.TemporaryDirectory(prefix="lomi-native-timeout-") as home:
        os.chmod(home, 0o700)
        directory = Path(home)
        helper = directory / "stalled_helper.py"
        # This synthetic helper never reads stdin and cannot exit because of EOF.
        helper.write_text(
            "#!" + str(Path(sys.executable).resolve()) + "\n"
            "import os, pathlib, signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_DFL)\n"
            "pathlib.Path(__file__).with_suffix('.pid').write_text(str(os.getpid())+' '+str(os.getpgrp()))\n"
            "deadline=time.monotonic()+10\n"
            "while time.monotonic()<deadline: time.sleep(1)\n"
        )
        helper.chmod(0o700)
        wrapper = directory / "stalled_driver.py"
        wrapper.write_text(
            "import importlib.util, os, pathlib, resource, signal, time\n"
            "resource.setrlimit(resource.RLIMIT_CORE,(0,0))\n"
            "signal.signal(signal.SIGTERM,signal.SIG_DFL)\n"
            f"spec=importlib.util.spec_from_file_location('driver',{str(Path(__file__).resolve())!r})\n"
            "driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)\n"
            "driver.owned.initialize_process_ownership()\n"
            f"peer=driver.Peer(pathlib.Path({str(helper)!r}),{home!r})\n"
            "pathlib.Path(__file__).with_suffix('.pid').write_text(str(os.getpid())+' '+str(os.getpgrp()))\n"
            "while True: time.sleep(1)\n"
        )
        env = {"HOME": home, "TMPDIR": home, "PATH": "/usr/bin:/bin",
               "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"}
        started = time.monotonic()
        timed_out = False
        try:
            owned.run_owned([sys.executable, str(wrapper)], cwd=home, env=env, timeout=1)
        except subprocess.TimeoutExpired:
            timed_out = True
        if not timed_out:
            raise RuntimeError("timeout regression did not time out")
        markers = [list(map(int, path.with_suffix(".pid").read_text().split()))
                   for path in (wrapper, helper)]
        pids = [marker[0] for marker in markers]
        if not all(len(marker) == 2 and marker[1] == pids[0] for marker in markers):
            raise RuntimeError("helper escaped the owned outer group")
        # PID files are diagnostic only. Cleanup exclusively used the retained
        # Popen leader's group; these IDs are never used as signal authority.
        gone = []
        for pid in pids:
            result = owned.run_owned(
                ["/bin/ps", "-o", "stat=", "-p", str(pid)],
                cwd=home, env=env, timeout=2,
            )
            gone.append(inspector_exited(result))
        elapsed = time.monotonic() - started
        if not all(gone) or elapsed >= 5 or elapsed >= 10:
            raise RuntimeError("timeout cleanup not proved before helper failsafe")
    return dict(ok=True, outerTimeoutObserved=True, driverGone=gone[0],
                helperGone=gone[1], helperNeverReadsStdin=True, processCount=2,
                sharedOuterProcessGroup=True, inspectorDecisionControls=control_count,
                inspectorFailuresRejected=True, elapsedSeconds=elapsed,
                elapsedBelowFiveSeconds=True, helperFailsafeSeconds=10,
                driverSourceSha256=digest(__file__))


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--timeout-regression"]:
            summary = run_timeout_regression()
        else:
            binary = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else ROOT / "target/debug/examples/transport_authority"
            summary = run(binary)
        print(json.dumps(summary, sort_keys=True))
    except BaseException:
        # Never print exceptions, incoming commands, tokens, plaintext or frames.
        print(json.dumps({"ok": False, "error": "NATIVE_FIXTURE_REJECTED"}))
        sys.exit(1)
