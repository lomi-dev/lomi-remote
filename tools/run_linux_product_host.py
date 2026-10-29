#!/usr/bin/env python3
"""Freeze and test the product host in the existing disposable lomi-e0 VM."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import tarfile
import uuid

from owned_process import initialize_process_ownership, run_owned
from source_manifest import source_inventory

ROOT = Path(__file__).resolve().parents[1]
LIMA = "/opt/homebrew/bin/limactl"


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    service_modes = parser.add_mutually_exclusive_group()
    service_modes.add_argument("--with-service", action="store_true",
                        help="also exercise a temporary systemd-user login service in the disposable guest")
    service_modes.add_argument("--with-boot-service", action="store_true",
                        help="qualify the temporary systemd-user boot service across a cold Lima stop/start")
    args = parser.parse_args()
    if not args.run:
        print("Not run: pass --run to use disposable VM lomi-e0; no service installation or reboot.")
        return 0
    run_id = str(uuid.uuid4())
    directory = ROOT / "artifacts/product-linux" / run_id
    directory.mkdir(parents=True, mode=0o700)
    report_path = directory / "report.json"
    remote_root = "/home/lomi-e0/lomi-product-" + run_id
    remote_archive = remote_root + ".tar.gz"
    environment = {**os.environ, "LIMA_HOME": str(ROOT / "artifacts/lima")}
    report = {"runId": run_id, "kind": "linux-product-host",
              "startedAt": datetime.now(timezone.utc).isoformat(),
              "complete": False, "passed": False, "qualified": False,
              "remoteCompletionKnown": True,
              "operations": [], "cleanup": {},
              "serviceRequested": args.with_service or args.with_boot_service,
              "bootServiceRequested": args.with_boot_service,
              "scope": "Product Unix host/CLI/PTY; optional temporary guest user service; no account or relay qualification."}

    def persist():
        temporary = report_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(temporary, report_path)

    def invoke(label, command, timeout=60):
        operation = {"name": label, "command": command, "complete": False}
        report["operations"].append(operation)
        persist()
        remote_operation = command[0] in ("ssh", LIMA)
        try:
            result = run_owned(command, cwd=ROOT, env=environment, timeout=timeout)
        except BaseException as error:
            operation["errorClass"] = type(error).__name__
            if remote_operation:
                report["remoteCompletionKnown"] = False
                operation["remoteCompletionKnown"] = False
            persist()
            raise
        log = directory / (label + ".log")
        log.write_text(result.stdout + result.stderr)
        operation.update(complete=True, exitCode=result.returncode,
                         log=log.name, logSha256=hashlib.sha256(log.read_bytes()).hexdigest())
        if remote_operation:
            known = result.returncode >= 0 and result.returncode != 255
            operation["remoteCompletionKnown"] = known
            report["remoteCompletionKnown"] &= known
        persist()
        if result.returncode:
            raise RuntimeError(label)
        return result.stdout

    persist()
    remote_created = False
    service_attempted = False
    cleanup_confirmed = False
    try:
        inventory = source_inventory(ROOT)
        report["sourceInventory"] = inventory
        report["driverSha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        archive = directory / "source.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for relative, expected in inventory["files"].items():
                data = (ROOT / relative).read_bytes()
                if hashlib.sha256(data).hexdigest() != expected:
                    raise RuntimeError("Source changed while freezing")
                entry = tarfile.TarInfo(relative)
                entry.size = len(data)
                entry.mode = 0o644
                output.addfile(entry, io.BytesIO(data))
        report["sourceArchiveSha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        public = invoke("vm-public-host-key", [LIMA, "shell", "--workdir=/", "lomi-e0",
                                               "cat", "/etc/ssh/ssh_host_ed25519_key.pub"])
        fields = public.split()
        if len(fields) < 2 or fields[0] != "ssh-ed25519":
            raise RuntimeError("Unexpected VM host key")
        instance = json.loads(invoke("vm-identity", [LIMA, "list", "lomi-e0", "--json"]))
        if instance["status"] != "Running" or instance["name"] != "lomi-e0":
            raise RuntimeError("Disposable VM is not running")
        port = int(instance["sshLocalPort"])
        known = directory / "known_hosts"
        known.write_text(f"[127.0.0.1]:{port} {fields[0]} {fields[1]}\n")
        os.chmod(known, 0o600)
        ssh = ["ssh", "-F", str(ROOT / "artifacts/lima/lomi-e0/ssh.config"),
               "-oControlMaster=no", "-oControlPath=none", "-oControlPersist=no",
               "-oStrictHostKeyChecking=yes", "-oNoHostAuthenticationForLocalhost=no",
               "-oGlobalKnownHostsFile=/dev/null", "-oUserKnownHostsFile=" + str(known),
               "-oBatchMode=yes", "-oConnectTimeout=10", "-T", "lima-lomi-e0"]

        def python(label, code, timeout=60):
            return invoke(label, ssh + [shlex.join(["python3", "-c", code])], timeout)

        create = f"from pathlib import Path; p=Path({remote_root!r}); p.mkdir(mode=0o700); (p/'.fixture-marker').write_text({run_id!r})"
        # Mark ownership before dispatch: a lost response must still attempt cleanup.
        remote_created = True
        python("create-private-run", create)
        invoke("copy-frozen-source", [LIMA, "copy", str(archive), "lomi-e0:" + remote_archive], 120)
        extract = f"""import hashlib, pathlib, tarfile
p=pathlib.Path({remote_root!r}); archive=pathlib.Path({remote_archive!r})
assert (p/'.fixture-marker').read_text()=={run_id!r}
assert hashlib.sha256(archive.read_bytes()).hexdigest()=={report['sourceArchiveSha256']!r}
source=p/'source'; source.mkdir()
with tarfile.open(archive) as t:
 assert all(m.isfile() and not pathlib.PurePosixPath(m.name).is_absolute() and '..' not in pathlib.PurePosixPath(m.name).parts for m in t.getmembers())
 t.extractall(source,filter='data')
"""
        python("extract-frozen-source", extract, 120)
        target = remote_root + "/target"
        cargo = ["env", "CARGO_BUILD_JOBS=2", "CARGO_INCREMENTAL=0", "CARGO_PROFILE_DEV_DEBUG=0",
                 "CARGO_TARGET_DIR=" + target, "/home/lomi-e0/.cargo/bin/cargo"]

        def cargo_command(label, arguments):
            command = "cd " + shlex.quote(remote_root + "/source") + " && " + shlex.join(cargo + arguments)
            return invoke(label, ssh + [command], 900)

        report["environment"] = json.loads(python("native-environment", "import json,platform; print(json.dumps({'os':platform.platform(),'machine':platform.machine(),'python':platform.python_version()}))"))
        cargo_command("build-product", ["build", "--locked", "-p", "lomiremote"])
        test_command = (
            "cd " + shlex.quote(remote_root + "/source")
            + " && PATH=/home/lomi-e0/.cargo/bin:$PATH env "
            + "CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 "
            + "CARGO_PROFILE_DEV_DEBUG=0 CARGO_TARGET_DIR=" + shlex.quote(target)
            + " LOMI_ONLINE=1 sh tools/test-host.sh "
            + "-p lomi-platform -p lomi-host-store -p lomi-terminal "
            + "-p lomi-host -p lomiremote"
        )
        invoke("native-product-tests", ssh + [test_command], 900)
        copy_binary = f"""import hashlib,json,pathlib,shutil
p=pathlib.Path({remote_root!r}); (p/'bin').mkdir(mode=0o700); b=p/'bin/lomiremote'
shutil.copyfile({target + '/debug/lomiremote'!r},b); b.chmod(0o500)
print(json.dumps({{'bytes':b.stat().st_size,'sha256':hashlib.sha256(b.read_bytes()).hexdigest(),
                  'directoryMode':(p/'bin').stat().st_mode & 0o777}}))
"""
        report["binary"] = json.loads(python("freeze-product-binary", copy_binary))
        if report["binary"].get("directoryMode") != 0o700:
            raise RuntimeError("Frozen binary directory is not private")
        helper = remote_root + "/source/tests/product-linux/continuity.py"
        for phase in ("prepare", "verify"):
            output = invoke("ssh-" + phase, ssh + [shlex.join(["python3", helper, phase,
                            "--root", remote_root, "--run-id", run_id])], 90)
            report[phase] = json.loads(output)
        # Successful return from prepare closed its independent SSH connection.
        report["independentSshConnections"] = True
        if args.with_service:
            service_helper = remote_root + "/source/tests/product-linux/service_lifecycle.py"
            service_attempted = True
            for phase in ("prepare", "verify"):
                output = invoke("ssh-service-" + phase, ssh + [shlex.join(["python3", service_helper, phase,
                                "--root", remote_root, "--run-id", run_id])], 180)
                report["service" + phase.title()] = json.loads(output)
        if args.with_boot_service:
            service_helper = remote_root + "/source/tests/product-linux/boot_service_lifecycle.py"
            service_attempted = True
            output = invoke("ssh-boot-service-prepare", ssh + [shlex.join(["python3", service_helper, "prepare",
                            "--root", remote_root, "--run-id", run_id])], 180)
            report["bootServicePrepare"] = json.loads(output)
            try:
                invoke("lima-cold-stop", [LIMA, "stop", "lomi-e0"], 180)
                invoke("lima-cold-start", [LIMA, "start", "lomi-e0"], 300)
            except BaseException:
                report["remoteCompletionKnown"] = False
                raise
            # Re-pin the host key and port after Lima's cold start.
            public = invoke("vm-public-host-key-after-boot", [LIMA, "shell", "--workdir=/", "lomi-e0",
                                                               "cat", "/etc/ssh/ssh_host_ed25519_key.pub"])
            fields = public.split()
            if len(fields) < 2 or fields[0] != "ssh-ed25519":
                raise RuntimeError("Unexpected VM host key after cold start")
            instance = json.loads(invoke("vm-identity-after-boot", [LIMA, "list", "lomi-e0", "--json"]))
            if instance["status"] != "Running" or instance["name"] != "lomi-e0":
                raise RuntimeError("Disposable VM did not return after cold start")
            port = int(instance["sshLocalPort"])
            known.write_text(f"[127.0.0.1]:{port} {fields[0]} {fields[1]}\n")
            os.chmod(known, 0o600)
            output = invoke("ssh-boot-service-verify", ssh + [shlex.join(["python3", service_helper, "verify",
                            "--root", remote_root, "--run-id", run_id])], 180)
            report["bootServiceVerify"] = json.loads(output)
    except BaseException as error:
        report["errorClass"] = type(error).__name__
    finally:
        if remote_created and report["remoteCompletionKnown"]:
            helper = remote_root + "/source/tests/product-linux/continuity.py"

            def cleanup_product():
                output = invoke("ssh-cleanup", ssh + [shlex.join(["python3", helper, "cleanup",
                                "--root", remote_root, "--run-id", run_id])], 90)
                report["cleanup"]["product"] = json.loads(output)
                if report["cleanup"]["product"].get("passed") is not True:
                    raise RuntimeError("Unconfirmed product cleanup")

            def cleanup_service():
                helper_name = "boot_service_lifecycle.py" if args.with_boot_service else "service_lifecycle.py"
                service_helper = remote_root + "/source/tests/product-linux/" + helper_name
                output = invoke("ssh-service-cleanup", ssh + [shlex.join(["python3", service_helper, "cleanup",
                                "--root", remote_root, "--run-id", run_id])], 180)
                report["cleanup"]["service"] = json.loads(output)
                if report["cleanup"]["service"].get("passed") is not True:
                    raise RuntimeError("Unconfirmed service cleanup")

            def remove_owned_inputs():
                remove = f"""from pathlib import Path; import shutil
p=Path({remote_root!r}); assert p.name=={'lomi-product-'+run_id!r} and (p/'.fixture-marker').read_text()=={run_id!r}
shutil.rmtree(p); Path({remote_archive!r}).unlink(missing_ok=True)
print('owned inputs removed')
"""
                python("remove-owned-inputs", remove, 60)
            if args.with_boot_service:
                product_clean = False
                service_clean = not service_attempted
                # Uninstalling the boot service first stops its daemon in the
                # separate profile; continuity cleanup then checks its own lock.
                if service_attempted:
                    try:
                        cleanup_service()
                        service_clean = True
                    except BaseException as error:
                        report["cleanup"]["serviceErrorClass"] = type(error).__name__
                # A known nonzero SSH result still permits the next cleanup.
                # Transport uncertainty means no later remote action is trusted.
                if report["remoteCompletionKnown"]:
                    try:
                        cleanup_product()
                        product_clean = True
                    except BaseException as error:
                        report["cleanup"]["productErrorClass"] = type(error).__name__
                if product_clean and service_clean and report["remoteCompletionKnown"]:
                    try:
                        remove_owned_inputs()
                        cleanup_confirmed = True
                    except BaseException as error:
                        report["cleanup"]["errorClass"] = type(error).__name__
                if not cleanup_confirmed:
                    report["cleanup"]["errorClass"] = report["cleanup"].get("errorClass", "CleanupUnconfirmed")
                    report["cleanup"]["preservedRemoteRoot"] = remote_root
            else:
                try:
                    if service_attempted:
                        cleanup_service()
                    cleanup_product()
                    remove_owned_inputs()
                    cleanup_confirmed = True
                except BaseException as error:
                    report["cleanup"]["errorClass"] = type(error).__name__
                    report["cleanup"]["preservedRemoteRoot"] = remote_root
        elif remote_created:
            report["cleanup"]["preservedRemoteRoot"] = remote_root
            report["cleanup"]["reason"] = "Remote completion is unconfirmed; preserve all owned inputs."
        report["cleanup"]["confirmed"] = cleanup_confirmed
        service_passed = not args.with_service or all(
            report.get("service" + phase, {}).get("passed") is True
            for phase in ("Prepare", "Verify")
        )
        boot_passed = not args.with_boot_service or report.get("bootServiceVerify", {}).get("passed") is True
        report["complete"] = bool(report.get("verify", {}).get("passed") and service_passed
                                  and boot_passed and cleanup_confirmed and "errorClass" not in report)
        report["passed"] = report["complete"]
        persist()
    print(json.dumps({"passed": report["passed"], "report": str(report_path.relative_to(ROOT))}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
