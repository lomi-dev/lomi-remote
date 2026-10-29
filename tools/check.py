#!/usr/bin/env python3
"""Reproduce local E0/E1 observations. Regression success does not qualify release."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from owned_process import initialize_process_ownership, run_owned


ROOT = Path(__file__).resolve().parents[1]
SCOPES = ("host", "consumer", "web", "git")


def command_version(argv):
    result = run_owned(argv, cwd=ROOT, timeout=10)
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def _legacy_main(args):
    output = args.output or ROOT / "artifacts/checks.json"
    report = {
        "kind": "e0-e1-regression-evidence", "generatedAt": datetime.now(timezone.utc).isoformat(),
        "stageQualified": False,
        "environment": {"os": platform.platform(), "machine": platform.machine(),
                        "python": platform.python_version(), "rustc": command_version(["rustc", "--version"]),
                        "cargo": command_version(["cargo", "--version"]),
                        "node": command_version(["node", "--version"]),
                        "bun": command_version(["bun", "--version"])},
        "checks": [],
    }
    commands = [
        ("format", ["cargo", "fmt", "--all", "--", "--check"], 0),
        ("lint", ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"], 0),
        ("rust-regressions", ["cargo", "test", "--workspace", "--locked"], 0),
        ("crypto-v3-regressions", ["cargo", "test", "--locked", "-p", "lomi-remote-crypto", "--features", "browser,test-fixtures"], 0),
        ("durable-update-crash-regressions", ["cargo", "test", "--locked", "-p", "lomi-update-trust", "--features", "fault-injection"], 0),
        ("schema-drift", ["cargo", "run", "--locked", "--quiet", "-p", "lomi-remote-protocol", "--bin", "generate-contracts", "--", "--check"], 0),
        ("install-remote-contract-dependencies", ["npm", "ci", "--prefix", "packages/remote-contracts", "--ignore-scripts", "--no-audit", "--no-fund"], 0),
        ("remote-contract-sdk-drift", ["npm", "run", "check", "--prefix", "packages/remote-contracts"], 0),
        ("protocol-codec-wasm-drift", ["npm", "run", "check", "--prefix", "packages/protocol-codec-wasm"], 0),
        ("protocol-codec-wasm-regressions", ["npm", "test", "--prefix", "packages/protocol-codec-wasm"], 0),
        ("remote-contract-sdk-regressions", ["npm", "test", "--prefix", "packages/remote-contracts"], 0),
        ("remote-contract-sdk-typecheck", ["npm", "run", "typecheck", "--prefix", "packages/remote-contracts"], 0),
        ("authority-crypto-release-wasm-drift", ["npm", "run", "check", "--prefix", "packages/authority-crypto-wasm"], 0),
        ("authority-crypto-node-regressions", ["npm", "test", "--prefix", "packages/authority-crypto-wasm"], 0),
        ("authority-crypto-bun-regressions", ["npm", "run", "test:bun", "--prefix", "packages/authority-crypto-wasm"], 0),
        ("authority-crypto-typecheck", ["node", "packages/remote-contracts/node_modules/typescript/bin/tsc", "--noEmit", "--strict", "--module", "nodenext", "--target", "es2022", "packages/authority-crypto-wasm/test/types.ts"], 0),
        ("authority-crypto-package-boundaries", [sys.executable, "-m", "unittest", "discover", "-s", "tools", "-p", "test_package_authority_crypto.py", "-v"], 0),
        ("tool-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/tools", "-v"], 0),
        ("linux-service-evidence-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/services-linux", "-p", "test_*.py", "-v"], 0),
        ("macos-service-runner-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/services-macos", "-p", "test_*.py", "-v"], 0),
        ("desktop-admission-runner-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/desktop-admission", "-p", "test_*.py", "-v"], 0),
        ("desktop-gui-runner-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/desktop-e0", "-p", "test_*.py", "-v"], 0),
        ("windows-cleanup-preservation-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/services-windows", "-p", "test_*.py", "-v"], 0),
        ("windows-product-scm-acceptance-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/product-scm-windows", "-p", "test_*.py", "-v"], 0),
        ("windows-product-service-acceptance-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/product-service-windows", "-p", "test_*.py", "-v"], 0),
        ("windows-product-login-acceptance-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/product-login-windows", "-p", "test_*.py", "-v"], 0),
        ("windows-product-dpapi-acceptance-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/product-dpapi-windows", "-p", "test_*.py", "-v"], 0),
        ("windows-wasi-git-runner-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/git-wasi-windows", "-p", "test_runner.py", "-v"], 0),
        ("linux-wasi-git-runner-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/git-wasi-linux", "-p", "test_runner.py", "-v"], 0),
        ("protocol-browser-runner-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/protocol-browser", "-p", "test_*.py", "-v"], 0),
        ("linux-git-prerequisite-lifecycle-regressions", [sys.executable, "tests/git-linux-isolation/profile_lifecycle.py"], 0),
        ("linux-git-runner-cleanup-regressions", [sys.executable, "tests/git-linux-isolation/runner_lifecycle.py"], 0),
        ("authority-fixture-lifecycle-regressions", ["node", "--test", "tests/authority-lock/lifecycle.test.mjs"], 0),
        ("crypto-source-provenance", [sys.executable, "tools/check_crypto_source.py"], 0),
        ("crypto-source-corruption-regressions", [sys.executable, "-m", "unittest", "discover", "-s", "tests/crypto-provenance", "-v"], 0),
        ("terminal-vendor-provenance", [sys.executable, "tools/check_terminal_vendor.py"], 0),
        ("release-fixture-provenance", [sys.executable, "tests/release/verify_fixtures.py"], 0),
        ("tuf-regressions", ["cargo", "run", "--locked", "--quiet", "-p", "lomi-release-spike", "--", "regression"], 0),
        ("tuf-qualification-rejected", ["cargo", "run", "--locked", "--quiet", "-p", "lomi-release-spike", "--", "qualify"], 1),
        ("install-development-oracle", ["npm", "ci", "--prefix", "tests/terminal", "--ignore-scripts", "--no-audit", "--no-fund"], 0),
        ("xterm-regressions", ["npm", "test", "--prefix", "tests/terminal"], 0),
        ("native-terminal-qualification-rejected", ["cargo", "run", "--locked", "--quiet", "-p", "lomi-terminal-spike", "--", "qualify"], 1),
        ("xterm-terminal-qualification-rejected", ["npm", "run", "qualify", "--prefix", "tests/terminal"], 1),
        ("install-structured-renderer-oracle", ["npm", "ci", "--prefix", "packages/terminal-renderer", "--ignore-scripts", "--no-audit", "--no-fund"], 0),
        ("structured-renderer-regressions", ["npm", "test", "--prefix", "packages/terminal-renderer"], 0),
        ("rust-structured-renderer-oracle", [sys.executable, "tools/check_terminal_state.py"], 0),
        ("interactive-vim-renderer-oracle", [sys.executable, "tools/check_terminal_state.py", "--interactive"], 0),
        ("install-pinned-test-browser", ["node", "packages/terminal-renderer/node_modules/playwright/cli.js", "install", "chromium"], 0),
        ("structured-renderer-browser", ["npm", "run", "test:browser", "--prefix", "packages/terminal-renderer"], 0),
        ("protocol-browser-regressions", [sys.executable, "tests/protocol-browser/run.py"], 0),
        ("crypto-v3-native-wasm-browser", [sys.executable, "tools/run_crypto_v3_browser.py", "--output", "artifacts/crypto-v3-browser/report.json"], 0),
        ("crypto-v3-native-peer-bounds", [sys.executable, "-m", "unittest", "discover", "-s", "tests/crypto-v3-browser", "-p", "test_*.py", "-v"], 0),
        ("source-provenance", [sys.executable, "tools/source_manifest.py", "--output", "artifacts/source-manifest.json"], 0),
        ("incomplete-release-rejected", [sys.executable, "tools/source_manifest.py", "--release", "--output", "artifacts/release-blockers.json"], 1),
    ]
    if platform.system() == "Darwin":
        commands.append(("native-session-pty-smoke", ["cargo", "run", "--locked", "--quiet", "-p", "lomi-platform-spike", "--bin", "pty-probe"], 0))
    if platform.system() in ("Darwin", "Linux"):
        commands.append(("product-interactive-terminal-attach", [sys.executable, "crates/lomiremote/tests/attach_pty.py", "target/debug/lomiremote"], 0))
    if args.pg_bin:
        commands.append(("enrollment-postgres-races", [sys.executable, "tools/run_enrollment_spike.py", "--pg-bin", str(args.pg_bin.resolve()), "--output", "artifacts/enrollment.json"], 0))
        commands.append(("actual-auth-postgres-bindings", [sys.executable, "tools/run_auth_binding_spike.py", "--pg-bin", str(args.pg_bin.resolve()), "--output", "artifacts/auth-binding.json"], 0))
        commands.append(("actual-auth-runner-shutdown-faults", [sys.executable, "-m", "unittest", "discover", "-s", "tests/auth-binding", "-p", "test_*.py", "-v"], 0))
        commands.append(("actual-relay-authorization-lock-load", [sys.executable, "tools/run_authority_lock_spike.py", "--pg-bin", str(args.pg_bin.resolve()), "--output", "artifacts/authority-lock/evidence.json"], 0))
    else:
        report["not_run"] = ["enrollment and actual Better Auth PostgreSQL proofs (supply --pg-bin)"]
    logs = (args.log_dir or ROOT / "artifacts/checks").resolve()
    # Every persisted artifact must remain a repository-relative evidence path.
    logs.relative_to(ROOT.resolve())
    logs.mkdir(parents=True, exist_ok=True)
    # A run is incomplete until every planned command returned as expected.
    failed = True
    exit_code = 1
    try:
        for name, argv, expected in commands:
            started = time.monotonic()
            kwargs = {}
            if name == "actual-auth-runner-shutdown-faults":
                # This explicit public tool path opts into real private-cluster
                # fault tests. Do not record inherited environment values.
                kwargs["env"] = {**os.environ, "AUTH_BINDING_TEST_PG_BIN": str(args.pg_bin.resolve())}
            result = run_owned(argv, cwd=ROOT, timeout=600, **kwargs)
            artifact = logs / f"{name}.log"
            # These commands emit aggregate diagnostics and synthetic fixtures.
            # Never add real user terminals, env, keys or credentials to this list.
            artifact.write_text(result.stdout + result.stderr)
            passed = result.returncode == expected
            report["checks"].append({"name": name, "command": argv, "expectedExitCode": expected,
                                     "exitCode": result.returncode, "regressionPassed": passed,
                                     "durationSeconds": round(time.monotonic() - started, 3),
                                     "artifact": artifact.relative_to(ROOT.resolve()).as_posix()})
            print(f"{name}: {'passed' if passed else 'failed'} (exit {result.returncode}, expected {expected})", flush=True)
            if not passed:
                break
        else:
            failed = False
            exit_code = 0
    except (OSError, subprocess.TimeoutExpired) as error:
        failed = True
        report["error"] = type(error).__name__
        print(f"check runner stopped: {type(error).__name__}", file=sys.stderr)
    except KeyboardInterrupt:
        report["error"] = "KeyboardInterrupt"
        exit_code = 130
        print("check runner interrupted; evidence remains incomplete", file=sys.stderr)
    finally:
        report["regressionsPassed"] = not failed
        report["completedChecks"] = len(report["checks"])
        report["plannedChecks"] = len(commands)
        report["complete"] = not failed and len(report["checks"]) == len(commands)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
    return exit_code


def _executable(path):
    if path is None:
        return None
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    candidate = candidate.absolute()
    return str(candidate) if candidate.is_file() and os.access(candidate, os.X_OK) else None


def _tool_override(value):
    if value is None:
        return None
    if os.sep not in value and (os.altsep is None or os.altsep not in value):
        return shutil.which(value)
    return _executable(value)


def _resolve_scope_tools(scope, args):
    """Resolve only tools used by a scope; never execute a tool here."""
    tools = {"python": str(Path(sys.executable).absolute())}

    def path_tool(name, override=None, repo_candidates=()):
        if override is not None:
            return _tool_override(override)
        for candidate in repo_candidates:
            found = _executable(candidate)
            if found:
                return found
        found = shutil.which(name)
        return str(Path(found).absolute()) if found else None

    if scope in ("host", "git"):
        tools["cargo"] = path_tool("cargo")
        tools["rustc"] = path_tool("rustc")
        tools["cargoHome"] = str(Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo").expanduser().resolve())
        tools["rustupHome"] = str(Path(os.environ.get("RUSTUP_HOME") or Path.home() / ".rustup").expanduser().resolve())
        if scope == "git":
            tools["git"] = path_tool("git")
    elif scope == "consumer":
        bun_candidates = []
        machine = platform.machine().lower()
        if platform.system() == "Darwin" and machine in ("arm64", "aarch64"):
            bun_candidates.extend((ROOT / "artifacts/toolchains").glob("bun-*-darwin-aarch64*/bun"))
        tools["bun"] = path_tool("bun", args.bun, bun_candidates)
        node_candidates = ()
        if platform.system() == "Darwin":
            node_candidates = (Path("/opt/homebrew/opt/node@22/bin/node"),
                               Path("/usr/local/opt/node@22/bin/node"))
        tools["node"] = path_tool("node", args.node, node_candidates)
        compiler_candidates = (
            ROOT.parent / "auth-app/node_modules/typescript/bin/tsc",
            ROOT / "node_modules/typescript/bin/tsc",
            ROOT.parent / "remote-web/node_modules/typescript/bin/tsc",
        )
        compiler = next((str(p.absolute()) for p in compiler_candidates
                         if p.is_file()), None)
        tools["typescript"] = compiler
        tools["typeRoots"] = [
            str(ROOT.parent / "auth-app/node_modules/@types"),
            str(ROOT / "node_modules/@types"),
        ]
    elif scope == "web":
        bun_candidates = []
        machine = platform.machine().lower()
        if platform.system() == "Darwin" and machine in ("arm64", "aarch64"):
            bun_candidates.extend((ROOT / "artifacts/toolchains").glob("bun-*-darwin-aarch64*/bun"))
        tools["bun"] = path_tool("bun", args.bun, bun_candidates)
        node_candidates = ()
        if platform.system() == "Darwin":
            node_candidates = (Path("/opt/homebrew/opt/node@22/bin/node"),
                               Path("/usr/local/opt/node@22/bin/node"))
        tools["node"] = path_tool("node", args.node, node_candidates)
        web_root = ROOT.parent / "remote-web"
        astro = web_root / "node_modules/astro/bin/astro.mjs"
        tools["astro"] = str(astro.absolute()) if astro.is_file() else None
        tools["astroAvailable"] = (astro.is_file()
                                   and (web_root / "node_modules/.bin/astro").is_file())
        astro_check = web_root / "node_modules/@astrojs/check/package.json"
        astro_typescript = web_root / "node_modules/typescript/package.json"
        tools["astroCheckEntry"] = str(astro_check.absolute()) if astro_check.is_file() else None
        tools["astroTypescriptEntry"] = str(astro_typescript.absolute()) if astro_typescript.is_file() else None
        tools["webRoot"] = str(web_root)
    return tools


def _scoped_commands(scope, tools):
    python = tools.get("python") or sys.executable
    commands = []
    skipped = []
    if scope == "host":
        cargo = tools.get("cargo") or "cargo"
        common = [cargo, "test", "--locked", "--offline", "--jobs", "2"]
        commands.extend([
            {"name": "host-http-unit-tests", "stage": "host-http",
             "command": [*common, "-p", "lomi-host-http", "--features", "test-fixtures", "--lib"],
             "cwd": str(ROOT), "timeoutSeconds": 600, "testRunner": "cargo"},
            {"name": "host-remote-connection-tests", "stage": "host-auth",
             "command": [*common, "-p", "lomi-host", "--features", "cloud-fixture", "--lib",
                         "unix::auth::remote_connection::tests"],
             "cwd": str(ROOT), "timeoutSeconds": 600, "testRunner": "cargo"},
            {"name": "host-ingress-driver-tests", "stage": "host-auth",
             "command": [*common, "-p", "lomi-host", "--features", "cloud-fixture", "--lib",
                         "ingress_driver_tests"],
             "cwd": str(ROOT), "timeoutSeconds": 600, "testRunner": "cargo"},
            {"name": "host-original-operation-deadline-tests", "stage": "host-auth",
             "command": [*common, "-p", "lomi-host", "--features", "cloud-fixture", "--lib",
                         "rollover_repro_tests"],
             "cwd": str(ROOT), "timeoutSeconds": 600, "testRunner": "cargo"},
            {"name": "host-git-executor-tests", "stage": "host-git",
             "command": [*common, "-p", "lomi-host", "--features", "cloud-fixture", "--lib",
                         "unix::remote_git::tests"],
             "cwd": str(ROOT), "timeoutSeconds": 600, "testRunner": "cargo"},
        ])
    elif scope == "git":
        commands.append({"name": "git-service-tests", "stage": "git-service",
                         "command": [tools.get("cargo") or "cargo", "test", "--locked", "--offline",
                                     "--jobs", "2", "-p", "lomi-git", "--lib"],
                         "cwd": str(ROOT), "timeoutSeconds": 600, "testRunner": "cargo"})
    elif scope == "consumer":
        consumer_dir = ROOT / "staging/consumer-scram"
        source_names = (
            "current_consumer_runtime_contract.ts",
            "current_consumer_runtime_contract.test.ts",
            "current_consumer_runtime_coordinator.ts",
            "current_consumer_runtime_coordinator.test.ts",
            "current_consumer_s5_adapter.ts",
            "current_consumer_s5_adapter.test.ts",
            "current_consumer_s5_reference_capture.ts",
            "current_consumer_s5_qualification.ts",
            "current_consumer_s5_qualification.test.ts",
        )
        type_roots = ",".join(tools.get("typeRoots", ()))
        commands.extend([
            {"name": "consumer-python-source-and-owner-tests", "stage": "consumer-python",
             "command": [python, "-B", "-m", "unittest", "-v",
                         "current_consumer_runtime_source_capture_test",
                         "test_current_consumer_runtime_owner"],
             "cwd": str(consumer_dir), "timeoutSeconds": 180, "testRunner": "unittest"},
            {"name": "consumer-runtime-bun-tests", "stage": "consumer-bun",
             "command": [tools.get("bun") or "bun", "--no-install", "--no-env-file", "test",
                         str(consumer_dir / "current_consumer_runtime_contract.test.ts"),
                         str(consumer_dir / "current_consumer_runtime_coordinator.test.ts"),
                         str(consumer_dir / "current_consumer_s5_adapter.test.ts"),
                         str(consumer_dir / "current_consumer_s5_qualification.test.ts")],
             "cwd": str(ROOT), "timeoutSeconds": 180, "testRunner": "bun"},
            {"name": "consumer-runtime-strict-types", "stage": "consumer-types",
             "command": [tools.get("node") or "node", tools.get("typescript") or "typescript/bin/tsc",
                         "--noEmit", "--strict", "--allowImportingTsExtensions", "--allowJs",
                         "--checkJs", "false", "--esModuleInterop", "--module", "ESNext",
                         "--moduleResolution", "Bundler", "--skipLibCheck", "--target", "ES2022",
                         "--types", "bun", "--typeRoots", type_roots,
                         *(str(consumer_dir / name) for name in source_names)],
             "cwd": str(ROOT), "timeoutSeconds": 180},
        ])
    elif scope == "web":
        web_root = tools.get("webRoot") or str(ROOT.parent / "remote-web")
        commands.append(
            {"name": "remote-web-bun-unit-tests", "stage": "web-unit",
             "command": [tools.get("bun") or "bun", "--no-install", "--no-env-file", "test", "tests"],
             "cwd": web_root, "timeoutSeconds": 300, "testRunner": "bun"},
        )
        if tools.get("astroAvailable") and tools.get("node"):
            commands.append(
                {"name": "remote-web-astro-check", "stage": "web-typecheck",
                 "command": [tools["node"], tools["astro"], "check"],
                 "cwd": web_root, "timeoutSeconds": 300},
            )
        elif tools.get("astroAvailable"):
            skipped.append({"name": "remote-web-astro-check",
                            "reason": "local Node is unavailable; no install attempted"})
        else:
            skipped.append({"name": "remote-web-astro-check",
                            "reason": "local Astro dependency is unavailable; no install attempted"})
    return commands, skipped


def _private_artifact_dir(scope):
    root = ROOT / "artifacts" / "scoped-checks"
    root.mkdir(parents=True, exist_ok=True)
    for _ in range(5):
        run_dir = root / f"{scope}-{uuid.uuid4()}"
        try:
            run_dir.mkdir(mode=0o700)
        except FileExistsError:
            continue
        info = run_dir.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise OSError("scoped artifact directory is not private")
        return run_dir
    raise FileExistsError("could not allocate a fresh scoped artifact directory")


def _private_execution_workspace(scope):
    base = Path("/private/tmp") if platform.system() == "Darwin" and Path("/private/tmp").is_dir() else Path("/tmp")
    path = Path(tempfile.mkdtemp(prefix=f"lc-{scope[0]}-", dir=base))
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise OSError("scoped execution workspace is not private")
    (path / "home").mkdir(mode=0o700)
    (path / "tmp").mkdir(mode=0o700)
    return path, (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))


def _remove_private_execution_workspace(path, identity):
    if path.name in ("", ".", "..") or "/" in path.name or "\x00" in path.name:
        raise OSError("execution workspace name changed")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(path.parent, flags)
    root_fd = None
    try:
        root_fd = os.open(path.name, flags, dir_fd=parent_fd)
        root_info = os.fstat(root_fd)
        named_root = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        root_identity = (root_info.st_dev, root_info.st_ino, root_info.st_uid,
                         stat.S_IMODE(root_info.st_mode))
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid()
                or stat.S_IMODE(root_info.st_mode) != 0o700 or root_identity != identity
                or (root_info.st_dev, root_info.st_ino, root_info.st_uid, root_info.st_mode)
                    != (named_root.st_dev, named_root.st_ino, named_root.st_uid, named_root.st_mode)):
            raise OSError("execution workspace identity changed")

        def remove_contents(directory_fd):
            for name in os.listdir(directory_fd):
                if name in ("", ".", "..") or "/" in name or "\x00" in name:
                    raise OSError("execution workspace entry name changed")
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if named.st_uid != os.geteuid() or named.st_dev != root_info.st_dev:
                    raise OSError("execution workspace contains an unowned entry")
                if stat.S_ISDIR(named.st_mode) and not stat.S_ISLNK(named.st_mode):
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(child_fd)
                        if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_mode) != (
                                named.st_dev, named.st_ino, named.st_uid, named.st_mode):
                            raise OSError("execution workspace directory changed")
                        remove_contents(child_fd)
                    finally:
                        os.close(child_fd)
                    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino):
                        raise OSError("execution workspace directory changed")
                    os.rmdir(name, dir_fd=directory_fd)
                elif stat.S_ISREG(named.st_mode) and named.st_nlink == 1:
                    file_flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                  | getattr(os, "O_NONBLOCK", 0))
                    file_fd = os.open(name, file_flags, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(file_fd)
                        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                                or (opened.st_dev, opened.st_ino, opened.st_uid)
                                    != (named.st_dev, named.st_ino, named.st_uid)):
                            raise OSError("execution workspace file changed")
                    finally:
                        os.close(file_fd)
                    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino):
                        raise OSError("execution workspace file changed")
                    os.unlink(name, dir_fd=directory_fd)
                else:
                    raise OSError("execution workspace contains an unsupported entry")

        remove_contents(root_fd)
        if os.listdir(root_fd):
            raise OSError("execution workspace is not empty")
        current_root = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if ((current_root.st_dev, current_root.st_ino, current_root.st_uid,
             stat.S_IMODE(current_root.st_mode)) != identity):
            raise OSError("execution workspace identity changed")
        os.close(root_fd)
        root_fd = None
        os.rmdir(path.name, dir_fd=parent_fd)
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)


def _scoped_environment(workspace, tools):
    paths = []
    for key in ("cargo", "rustc", "bun", "node", "git"):
        value = tools.get(key)
        if value:
            parent = str(Path(value).parent)
            if parent not in paths:
                paths.append(parent)
    for system_path in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if system_path not in paths:
            paths.append(system_path)
    home = workspace / "home"
    tmp = workspace / "tmp"
    environment = {
        "HOME": str(home), "TMPDIR": str(tmp), "TMP": str(tmp), "TEMP": str(tmp),
        "PATH": os.pathsep.join(paths), "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
        "CI": "true", "TERM": "dumb", "GIT_TERMINAL_PROMPT": "0",
        "ASTRO_TELEMETRY_DISABLED": "1", "npm_config_yes": "false",
        "BUN_CONFIG_NO_INSTALL": "1",
    }
    if "cargoHome" in tools:
        cargo_home = Path(tools["cargoHome"])
        rustup_home = Path(tools["rustupHome"])
        if not cargo_home.is_dir() or not rustup_home.is_dir():
            raise FileNotFoundError("existing Cargo and Rustup caches are required")
        environment.update({
            "CARGO_HOME": str(cargo_home), "RUSTUP_HOME": str(rustup_home),
            "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2",
            "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
            "CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never",
            "CARGO_TERM_PROGRESS_WHEN": "never",
        })
    return environment


def _validate_runner_result(result, command):
    if (not isinstance(result, subprocess.CompletedProcess)
            or result.args != command
            or type(result.returncode) is not int
            or not isinstance(result.stdout, str)
            or not isinstance(result.stderr, str)):
        raise TypeError("owned command runner returned an invalid result")


def _test_counts(test_runner, stdout, stderr):
    """Parse executed, passed, failed, and ignored tests from a test command."""
    text = stdout + "\n" + stderr
    counts = {"executed": 0, "passed": 0, "failed": 0, "ignored": 0,
              "summaryPresent": False}
    if test_runner == "cargo":
        summaries = re.findall(
            r"(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
            r"(\d+) ignored;",
            text,
        )
        if not summaries:
            return counts
        counts["summaryPresent"] = True
        for _, passed, failed, ignored in summaries:
            counts["passed"] += int(passed)
            counts["failed"] += int(failed)
            counts["ignored"] += int(ignored)
        counts["executed"] = counts["passed"] + counts["failed"]
        return counts

    if test_runner == "unittest":
        ran = re.search(r"(?m)^Ran (\d+) tests? in .+$", text)
        summary = re.search(r"(?m)^(OK|FAILED)(?: \(([^\n]*)\))?\s*$", text)
        if ran is None or summary is None:
            return counts
        total = int(ran.group(1))
        detail = summary.group(2) or ""

        def detail_count(name):
            match = re.search(rf"(?:^|, )\b{name}=(\d+)\b", detail)
            return int(match.group(1)) if match else 0

        ignored = detail_count("skipped")
        failed = (detail_count("failures") + detail_count("errors")
                  + detail_count("unexpected successes"))
        if summary.group(1) == "FAILED" and failed == 0:
            return counts
        passed = total - ignored - failed
        if min(total, ignored, failed, passed) < 0:
            return counts
        counts.update({"executed": total - ignored, "passed": passed,
                       "failed": failed, "ignored": ignored, "summaryPresent": True})
        return counts

    if test_runner == "bun":
        ran = re.search(r"(?m)^Ran (\d+) tests?\b", text)
        labels = {}
        for label in ("pass", "fail"):
            match = re.search(rf"(?m)^\s*(\d+) {label}\s*$", text)
            if match is None:
                return counts
            labels[label] = int(match.group(1))
        for label in ("skip", "todo"):
            match = re.search(rf"(?m)^\s*(\d+) {label}\s*$", text)
            labels[label] = int(match.group(1)) if match else 0
        if ran is None:
            return counts
        counts.update({"executed": labels["pass"] + labels["fail"],
                       "passed": labels["pass"], "failed": labels["fail"],
                       "ignored": labels["skip"] + labels["todo"],
                       "summaryPresent": True})
        return counts

    return counts


def _semantic_version(value):
    match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)", value)
    return tuple(int(part) for part in match.groups()) if match else None


def _write_private_report(report_path, report_file, report):
    report["report"] = str(report_path)
    report_file.seek(0)
    report_file.truncate()
    report_file.write(json.dumps(report, indent=2) + "\n")
    report_file.flush()
    os.fsync(report_file.fileno())


def _run_scoped(args):
    scope = args.scope
    run_dir = _private_artifact_dir(scope)
    worklog_path = run_dir / "worklog.log"
    worklog_fd = os.open(worklog_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    worklog = os.fdopen(worklog_fd, "w", encoding="utf-8")
    report_path = run_dir / "report.json"
    explicit_output_rejected = False
    output_error = None
    if args.output is not None:
        requested = args.output.expanduser()
        if not requested.is_absolute():
            requested = Path.cwd() / requested
        requested = requested.absolute()
        try:
            requested.parent.mkdir(parents=True, exist_ok=True)
            report_fd = os.open(requested, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            report_path = requested
        except OSError as error:
            explicit_output_rejected = True
            output_error = type(error).__name__
            report_path = run_dir / "report.json"
            report_fd = os.open(report_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    else:
        report_fd = os.open(report_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    report_file = os.fdopen(report_fd, "w", encoding="utf-8")
    report = {
        "kind": "scoped-product-verification", "generatedAt": datetime.now(timezone.utc).isoformat(),
        "scope": scope, "stageQualified": False,
        "environment": {"os": platform.platform(), "machine": platform.machine(),
                        "python": platform.python_version()},
        "runtime": {"toolPaths": {}, "versions": {}, "probes": []},
        "commands": [], "skipped": [], "failure": None,
        "regressionsPassed": False, "complete": False,
        "worklog": str(worklog_path),
    }
    if explicit_output_rejected:
        report["failure"] = {"stage": "output",
                             "reason": "requested output could not be created exclusively; no checks were run",
                             "error": output_error}

    workspace = None
    workspace_identity = None
    workspace_retained = True
    runner_integrity_unknown = False
    exit_code = 1

    def log(record, stdout="", stderr=""):
        worklog.write(json.dumps(record, sort_keys=True) + "\n")
        if stdout:
            worklog.write("--- stdout ---\n" + stdout)
            if not stdout.endswith("\n"):
                worklog.write("\n")
        if stderr:
            worklog.write("--- stderr ---\n" + stderr)
            if not stderr.endswith("\n"):
                worklog.write("\n")
        worklog.flush()

    try:
        workspace, workspace_identity = _private_execution_workspace(scope)
        report["executionWorkspace"] = str(workspace)
        tools = _resolve_scope_tools(scope, args)
        report["runtime"]["toolPaths"] = {
            key: value for key, value in tools.items()
            if key in ("python", "cargo", "rustc", "bun", "node", "git", "typescript", "astro",
                       "astroCheckEntry", "astroTypescriptEntry") and value
        }
        commands, skipped = _scoped_commands(scope, tools)
        report["skipped"] = skipped
        report["plannedChecks"] = len(commands)
        required = {
            "host": ("cargo", "rustc"),
            "git": ("cargo", "rustc", "git"),
            "consumer": ("bun", "node", "typescript"),
            "web": ("bun",),
        }[scope]
        if scope == "web" and tools.get("astroAvailable"):
            required = (*required, "node")
        missing = [name for name in required if not tools.get(name)]
        if missing:
            report["failure"] = {"stage": "preflight", "reason": "required local tool unavailable",
                                 "tools": missing}
        elif report["failure"] is None:
            environment = _scoped_environment(workspace, tools)
            version_commands = []
            if scope in ("host", "git"):
                version_commands = [("cargo", [tools["cargo"], "--version"]),
                                    ("rustc", [tools["rustc"], "--version"])]
                if scope == "git":
                    version_commands.append(("git", [tools["git"], "--version"]))
            elif scope == "consumer":
                version_commands = [("bun", [tools["bun"], "--no-install", "--no-env-file", "--version"]),
                                    ("node", [tools["node"], "--version"]),
                                    ("typescript", [tools["node"], tools["typescript"], "--version"])]
            elif scope == "web":
                version_commands = [("bun", [tools["bun"], "--no-install", "--no-env-file", "--version"])]
                if tools.get("astroAvailable") and tools.get("node"):
                    version_commands.append(("node", [tools["node"], "--version"]))
            for name, command in version_commands:
                started = time.monotonic()
                log({"kind": "runtime-probe", "name": name, "command": command,
                     "cwd": str(ROOT), "timeoutSeconds": 10})
                try:
                    result = run_owned(command, cwd=ROOT, env=environment, timeout=10)
                    _validate_runner_result(result, command)
                except BaseException as error:
                    runner_integrity_unknown = True
                    report["failure"] = {"stage": "runtime", "name": name,
                                         "reason": "owned command runner did not return a valid terminal result",
                                         "error": type(error).__name__}
                    if isinstance(error, KeyboardInterrupt):
                        exit_code = 130
                    break
                duration = round(time.monotonic() - started, 3)
                probe = {"name": name, "command": command, "exitCode": result.returncode,
                         "durationSeconds": duration}
                report["runtime"]["probes"].append(probe)
                log({"kind": "runtime-result", **probe}, result.stdout, result.stderr)
                if result.returncode != 0:
                    report["failure"] = {"stage": "runtime", "name": name,
                                         "reason": "runtime version command failed",
                                         "exitCode": result.returncode}
                    break
                version = result.stdout.strip()
                report["runtime"]["versions"][name] = version
                if (scope == "web" and name == "node" and tools.get("astroAvailable")
                        and (_semantic_version(version) or (0, 0, 0)) < (22, 12, 0)):
                    report["failure"] = {"stage": "runtime", "name": "node",
                                         "reason": "Astro check requires Node 22.12.0 or newer"}
                    break

            if (report["failure"] is None and scope == "web"
                    and tools.get("astroAvailable") and tools.get("node")):
                command = [tools["node"], "-e",
                           "for (const name of ['@astrojs/check', 'typescript']) "
                           "console.log(require.resolve(name, { paths: [process.cwd()] }));"]
                started = time.monotonic()
                log({"kind": "local-dependency-preflight", "name": "astro-check-dependencies",
                     "command": command, "cwd": tools["webRoot"], "timeoutSeconds": 10})
                try:
                    result = run_owned(command, cwd=tools["webRoot"], env=environment, timeout=10)
                    _validate_runner_result(result, command)
                except BaseException as error:
                    runner_integrity_unknown = True
                    report["failure"] = {"stage": "preflight", "name": "astro-check-dependencies",
                                         "reason": "local Astro check dependency resolution did not return a valid result",
                                         "error": type(error).__name__}
                    if isinstance(error, KeyboardInterrupt):
                        exit_code = 130
                else:
                    probe = {"name": "astro-check-dependencies", "command": command,
                             "exitCode": result.returncode,
                             "durationSeconds": round(time.monotonic() - started, 3)}
                    report["runtime"]["probes"].append(probe)
                    log({"kind": "local-dependency-result", **probe}, result.stdout, result.stderr)
                    if result.returncode != 0:
                        report["failure"] = {"stage": "preflight", "name": "astro-check-dependencies",
                                             "reason": "local @astrojs/check or TypeScript is unavailable; no install attempted",
                                             "exitCode": result.returncode}
                    else:
                        report["runtime"]["astroCheckDependencies"] = result.stdout.splitlines()

            if report["failure"] is None:
                for item in commands:
                    command = item["command"]
                    started = time.monotonic()
                    log({"kind": "check", "name": item["name"], "stage": item["stage"],
                         "command": command, "cwd": item["cwd"],
                         "timeoutSeconds": item["timeoutSeconds"]})
                    try:
                        result = run_owned(command, cwd=item["cwd"], env=environment,
                                           timeout=item["timeoutSeconds"])
                        _validate_runner_result(result, command)
                    except BaseException as error:
                        runner_integrity_unknown = True
                        report["failure"] = {"stage": item["stage"], "name": item["name"],
                                             "reason": "owned command runner did not return a valid terminal result",
                                             "error": type(error).__name__}
                        if isinstance(error, KeyboardInterrupt):
                            exit_code = 130
                        break
                    duration = round(time.monotonic() - started, 3)
                    test_counts = None
                    passed = result.returncode == 0
                    failure_reason = "command returned an unexpected exit code"
                    if item.get("testRunner"):
                        test_counts = _test_counts(item["testRunner"], result.stdout, result.stderr)
                        if not test_counts["summaryPresent"]:
                            passed = False
                            failure_reason = "test command emitted no recognized summary"
                        elif test_counts["executed"] == 0:
                            passed = False
                            failure_reason = "test command ran zero non-ignored tests"
                        elif test_counts["failed"] != 0 or test_counts["passed"] == 0:
                            passed = False
                            failure_reason = "test command did not report passing tests only"
                        elif result.returncode != 0:
                            passed = False
                    row = {"name": item["name"], "stage": item["stage"],
                           "command": command, "cwd": item["cwd"], "expectedExitCode": 0,
                           "exitCode": result.returncode, "passed": passed,
                           "durationSeconds": duration}
                    if test_counts is not None:
                        row["testCounts"] = test_counts
                    report["commands"].append(row)
                    log({"kind": "check-result", **row}, result.stdout, result.stderr)
                    print(f"{item['name']}: {'passed' if passed else 'failed'} "
                          f"(exit {result.returncode}, expected 0)", flush=True)
                    if not passed:
                        report["failure"] = {"stage": item["stage"], "name": item["name"],
                                             "reason": failure_reason,
                                             "exitCode": result.returncode}
                        break
                else:
                    if not commands:
                        report["failure"] = {"stage": "preflight", "reason": "scope has no executable checks"}
                    else:
                        exit_code = 0
    except BaseException as error:
        runner_integrity_unknown = True
        report["failure"] = {"stage": "runner", "reason": "scoped runner stopped before completion",
                             "error": type(error).__name__}
        if isinstance(error, KeyboardInterrupt):
            exit_code = 130
    finally:
        if workspace is not None and workspace_identity is not None and not runner_integrity_unknown:
            try:
                _remove_private_execution_workspace(workspace, workspace_identity)
                workspace_retained = False
            except OSError as error:
                report["failure"] = {"stage": "cleanup", "reason": "private workspace cleanup refused",
                                     "error": type(error).__name__}
                exit_code = 1
        report["executionWorkspaceRetained"] = workspace_retained
        report["executionWorkspaceCleanupPassed"] = workspace is not None and not workspace_retained
        report["completedChecks"] = len(report["commands"])
        report["regressionsPassed"] = (
            bool(report["commands"])
            and report["failure"] is None
            and len(report["commands"]) == report.get("plannedChecks", -1)
            and all(item["passed"] for item in report["commands"])
        )
        report["complete"] = report["regressionsPassed"]
        if report["regressionsPassed"]:
            exit_code = 0
        elif exit_code == 0:
            exit_code = 1
        log({"kind": "final", "exitCode": exit_code,
             "executionWorkspaceRetained": workspace_retained,
             "failure": report["failure"]})
        try:
            _write_private_report(report_path, report_file, report)
        finally:
            report_file.close()
            worklog.close()
        print(f"scoped report: {report_path}", flush=True)
        print(f"private worklog: {worklog_path}", flush=True)
        if workspace_retained and workspace is not None:
            print(f"private execution workspace retained: {workspace}", flush=True)
    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        help="write the JSON report to a fresh path (scoped runs refuse existing files)")
    parser.add_argument("--log-dir", type=Path,
                        help="write command logs in a separate directory to preserve earlier evidence")
    parser.add_argument("--pg-bin", type=Path,
                        help="also run enrollment and actual Better Auth proofs in private PostgreSQL 17 clusters")
    parser.add_argument("--scope", choices=SCOPES,
                        help="run only the selected host, consumer, or web checks")
    parser.add_argument("--list", action="store_true",
                        help="list scoped commands without executing them (requires --scope)")
    parser.add_argument("--bun", help="override Bun executable for a scoped run")
    parser.add_argument("--node", help="override Node executable for a scoped run")
    args = parser.parse_args()

    if args.list:
        if args.scope is None:
            parser.error("--list requires --scope")
        tools = _resolve_scope_tools(args.scope, args)
        commands, skipped = _scoped_commands(args.scope, tools)
        required = {
            "host": ("cargo", "rustc"),
            "git": ("cargo", "rustc", "git"),
            "consumer": ("bun", "node", "typescript"),
            "web": ("bun", "node") if tools.get("astroAvailable") else ("bun",),
        }[args.scope]
        print(json.dumps({"scope": args.scope, "commands": commands, "skipped": skipped,
                          "missingTools": [name for name in required if not tools.get(name)]}, indent=2))
        return 0

    if args.scope is None:
        if args.bun or args.node:
            parser.error("--bun and --node require --scope")
        initialize_process_ownership()
        return _legacy_main(args)
    if args.log_dir is not None:
        parser.error("scoped runs keep one private worklog and do not accept --log-dir")
    if args.pg_bin is not None:
        parser.error("--pg-bin is only available in the legacy full run")
    initialize_process_ownership()
    return _run_scoped(args)


if __name__ == "__main__":
    raise SystemExit(main())
