from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))
try:
    spec = importlib.util.spec_from_file_location("e0_check_runner", TOOLS / "check.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
finally:
    sys.path.pop(0)


class CheckRunnerTests(unittest.TestCase):
    def test_interrupted_partial_run_is_never_recorded_as_passed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "result.json"
            first = subprocess.CompletedProcess(["synthetic-format"], 0, "", "")
            with (
                patch.object(runner, "ROOT", root),
                patch.object(runner, "command_version", return_value="synthetic"),
                patch.object(runner, "run_owned", side_effect=[first, KeyboardInterrupt]),
                patch.object(sys, "argv", ["check.py", "--output", str(output)]),
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(runner.main(), 130)
            evidence = json.loads(output.read_text())
            self.assertFalse(evidence["regressionsPassed"])
            self.assertFalse(evidence["complete"])
            self.assertFalse(evidence["stageQualified"])
            self.assertEqual(evidence["error"], "KeyboardInterrupt")
            self.assertEqual(evidence["completedChecks"], 1)
            self.assertGreater(evidence["plannedChecks"], 1)

    def test_scoped_command_lists_are_targeted_and_never_spawn(self):
        for scope in ("host", "consumer", "web", "git"):
            output = io.StringIO()
            with (
                patch.object(sys, "argv", ["check.py", "--scope", scope, "--list"]),
                patch.object(runner, "run_owned", side_effect=AssertionError("list executed a command")),
                redirect_stdout(output),
            ):
                self.assertEqual(runner.main(), 0)
            plan = json.loads(output.getvalue())
            self.assertEqual(plan["scope"], scope)
            self.assertGreater(len(plan["commands"]), 0)
            names = [item["name"] for item in plan["commands"]]
            if scope == "host":
                self.assertEqual(names, ["host-http-unit-tests", "host-remote-connection-tests",
                                         "host-ingress-driver-tests", "host-original-operation-deadline-tests",
                                         "host-git-executor-tests"])
                self.assertIn("unix::auth::remote_connection::tests", plan["commands"][1]["command"])
                self.assertIn("ingress_driver_tests", plan["commands"][2]["command"])
                self.assertTrue(all(item["testRunner"] == "cargo" for item in plan["commands"]))
            elif scope == "consumer":
                self.assertEqual(names, ["consumer-python-source-and-owner-tests",
                                         "consumer-runtime-bun-tests", "consumer-runtime-strict-types"])
                bun_command = plan["commands"][1]["command"]
                self.assertTrue(any(path.endswith("current_consumer_runtime_contract.test.ts")
                                    for path in bun_command))
                self.assertTrue(any(path.endswith("current_consumer_runtime_coordinator.test.ts")
                                    for path in bun_command))
                self.assertTrue(any(path.endswith("current_consumer_s5_adapter.test.ts")
                                    for path in bun_command))
                self.assertTrue(any(path.endswith("current_consumer_s5_qualification.test.ts")
                                    for path in bun_command))
                self.assertEqual(sum(path.endswith(".ts") for path in plan["commands"][2]["command"]), 9)
                self.assertEqual(plan["commands"][0]["testRunner"], "unittest")
                self.assertEqual(plan["commands"][1]["testRunner"], "bun")
            elif scope == "git":
                self.assertEqual(names, ["git-service-tests"])
                self.assertIn("lomi-git", plan["commands"][0]["command"])
                self.assertEqual(plan["commands"][0]["testRunner"], "cargo")
            else:
                self.assertEqual(names[0], "remote-web-bun-unit-tests")
                self.assertTrue(all("tests" in item["command"] for item in plan["commands"][:1]))
                if len(plan["commands"]) > 1:
                    astro = plan["commands"][1]
                    self.assertEqual(astro["name"], "remote-web-astro-check")
                    self.assertEqual(Path(astro["command"][0]).name, "node")
                    self.assertEqual(astro["command"][-1], "check")
            serialized = json.dumps(plan).lower()
            for forbidden in ("postgres", "pg-bin", "npm ci", "playwright", "ssh"):
                self.assertNotIn(forbidden, serialized)
            for item in plan["commands"]:
                command = item["command"]
                if Path(command[0]).name == "bun" or "bun" in Path(command[0]).name:
                    self.assertIn("--no-env-file", command)
                    self.assertIn("--no-install", command)
                if Path(command[0]).name == "cargo":
                    self.assertIn("--locked", command)
                    self.assertIn("--offline", command)

    def test_scoped_failure_uses_closed_environment_and_stops(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cargo_home = root / "cargo"
            rustup_home = root / "rustup"
            cargo_home.mkdir()
            rustup_home.mkdir()
            tools = {
                "python": sys.executable,
                "cargo": "/synthetic/bin/cargo",
                "rustc": "/synthetic/bin/rustc",
                "cargoHome": str(cargo_home),
                "rustupHome": str(rustup_home),
            }
            calls = []
            environments = []

            def fake_run(command, *, cwd=None, env=None, timeout=120):
                calls.append(command)
                environments.append(env)
                if command[-1] == "--version":
                    return subprocess.CompletedProcess(command, 0, "synthetic version\n", "")
                return subprocess.CompletedProcess(command, 7, "", "synthetic failure")

            with (
                patch.object(runner, "ROOT", root),
                patch.object(runner, "_resolve_scope_tools", return_value=tools),
                patch.object(runner, "run_owned", side_effect=fake_run),
                patch.dict(os.environ, {"CHECK_RUNNER_SECRET": "must-not-leak"}),
                patch.object(sys, "argv", ["check.py", "--scope", "host"]),
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(runner.main(), 1)

            report_path = next((root / "artifacts/scoped-checks").glob("host-*/report.json"))
            report = json.loads(report_path.read_text())
            self.assertFalse(report["regressionsPassed"])
            self.assertFalse(report["complete"])
            self.assertFalse(report["stageQualified"])
            self.assertEqual(report["completedChecks"], 1)
            self.assertEqual(report["commands"][0]["exitCode"], 7)
            self.assertEqual(len([call for call in calls if "test" in call]), 1)
            environment = environments[-1]
            self.assertNotIn("CHECK_RUNNER_SECRET", environment)
            self.assertEqual(environment["HOME"], str(Path(report["executionWorkspace"]) / "home"))
            self.assertEqual(environment["TMPDIR"], str(Path(report["executionWorkspace"]) / "tmp"))
            self.assertEqual(environment["CARGO_HOME"], str(cargo_home))
            self.assertEqual(environment["RUSTUP_HOME"], str(rustup_home))
            self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
            self.assertEqual(environment["CARGO_PROFILE_TEST_DEBUG"], "0")
            self.assertEqual(environment["CARGO_BUILD_JOBS"], "2")
            self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
            self.assertEqual(environment["CI"], "true")
            self.assertEqual(environment["TERM"], "dumb")
            self.assertFalse(Path(report["executionWorkspace"]).exists())
            self.assertTrue(report["executionWorkspaceCleanupPassed"])

    def test_invalid_runner_result_is_retained_and_stops_future_commands(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cargo_home = root / "cargo"
            rustup_home = root / "rustup"
            cargo_home.mkdir()
            rustup_home.mkdir()
            tools = {"python": sys.executable, "cargo": "/synthetic/bin/cargo",
                     "rustc": "/synthetic/bin/rustc", "cargoHome": str(cargo_home),
                     "rustupHome": str(rustup_home)}
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                if command[-1] == "--version":
                    return subprocess.CompletedProcess(command, 0, "synthetic version\n", "")
                return subprocess.CompletedProcess(command, 0, None, "")

            with (
                patch.object(runner, "ROOT", root),
                patch.object(runner, "_resolve_scope_tools", return_value=tools),
                patch.object(runner, "run_owned", side_effect=fake_run),
                patch.object(sys, "argv", ["check.py", "--scope", "host"]),
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(runner.main(), 1)

            report_path = next((root / "artifacts/scoped-checks").glob("host-*/report.json"))
            report = json.loads(report_path.read_text())
            workspace = Path(report["executionWorkspace"])
            worklog = Path(report["worklog"])
            self.assertTrue(report["executionWorkspaceRetained"])
            self.assertTrue(workspace.is_dir())
            self.assertFalse(report["regressionsPassed"])
            self.assertFalse(report["complete"])
            self.assertEqual(report["failure"]["error"], "TypeError")
            self.assertEqual(len([call for call in calls if "test" in call]), 1)
            self.assertEqual(worklog.stat().st_mode & 0o777, 0o600)
            self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(report_path.parent.stat().st_mode & 0o777, 0o700)

    def test_scoped_interruption_retains_partial_report_and_workspace(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cargo_home = root / "cargo"
            rustup_home = root / "rustup"
            cargo_home.mkdir()
            rustup_home.mkdir()
            tools = {"python": sys.executable, "cargo": "/synthetic/bin/cargo",
                     "rustc": "/synthetic/bin/rustc", "cargoHome": str(cargo_home),
                     "rustupHome": str(rustup_home)}
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                if command[-1] == "--version":
                    return subprocess.CompletedProcess(command, 0, "synthetic version\n", "")
                raise KeyboardInterrupt

            with (
                patch.object(runner, "ROOT", root),
                patch.object(runner, "_resolve_scope_tools", return_value=tools),
                patch.object(runner, "run_owned", side_effect=fake_run),
                patch.object(sys, "argv", ["check.py", "--scope", "host"]),
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(runner.main(), 130)

            report_path = next((root / "artifacts/scoped-checks").glob("host-*/report.json"))
            report = json.loads(report_path.read_text())
            self.assertFalse(report["regressionsPassed"])
            self.assertFalse(report["complete"])
            self.assertTrue(report["executionWorkspaceRetained"])
            self.assertTrue(Path(report["executionWorkspace"]).is_dir())
            self.assertEqual(report["completedChecks"], 0)
            self.assertEqual(report["failure"]["error"], "KeyboardInterrupt")
            self.assertEqual(len([call for call in calls if "test" in call]), 1)

    def test_scoped_output_refuses_to_replace_existing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cargo_home = root / "cargo"
            rustup_home = root / "rustup"
            cargo_home.mkdir()
            rustup_home.mkdir()
            existing = root / "result.json"
            existing.write_text("keep this report\n")
            tools = {"python": sys.executable, "cargo": "/synthetic/bin/cargo",
                     "rustc": "/synthetic/bin/rustc", "cargoHome": str(cargo_home),
                     "rustupHome": str(rustup_home)}
            with (
                patch.object(runner, "ROOT", root),
                patch.object(runner, "_resolve_scope_tools", return_value=tools),
                patch.object(runner, "run_owned", side_effect=AssertionError("existing output ran checks")),
                patch.object(sys, "argv", ["check.py", "--scope", "host", "--output", str(existing)]),
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(runner.main(), 1)
            self.assertEqual(existing.read_text(), "keep this report\n")
            report_path = next((root / "artifacts/scoped-checks").glob("host-*/report.json"))
            report = json.loads(report_path.read_text())
            self.assertEqual(report["failure"]["stage"], "output")
            self.assertFalse(report["regressionsPassed"])
            self.assertEqual(report["report"], str(report_path))

    def test_zero_test_success_is_recorded_as_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            tools = {"python": sys.executable, "bun": "/synthetic/bin/bun",
                     "node": "/synthetic/bin/node", "typescript": "/synthetic/tsc",
                     "typeRoots": []}
            calls = []

            def fake_run(command, **kwargs):
                calls.append(command)
                if "--version" in command:
                    if Path(command[0]).name == "bun":
                        version = "1.4.2\n"
                    elif command[-1] == "--version":
                        version = "Version 5.9.0\n"
                    else:
                        version = "v22.23.3\n"
                    return subprocess.CompletedProcess(command, 0, version, "")
                if "unittest" in command:
                    return subprocess.CompletedProcess(command, 0, "Ran 0 tests in 0.000s\n\nOK\n", "")
                self.fail("a zero-test success must stop the scoped run")

            with (
                patch.object(runner, "ROOT", root),
                patch.object(runner, "_resolve_scope_tools", return_value=tools),
                patch.object(runner, "run_owned", side_effect=fake_run),
                patch.object(sys, "argv", ["check.py", "--scope", "consumer"]),
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(runner.main(), 1)

            report_path = next((root / "artifacts/scoped-checks").glob("consumer-*/report.json"))
            report = json.loads(report_path.read_text())
            self.assertFalse(report["regressionsPassed"])
            self.assertFalse(report["complete"])
            self.assertEqual(report["completedChecks"], 1)
            self.assertEqual(report["commands"][0]["testCounts"], {
                "executed": 0, "passed": 0, "failed": 0, "ignored": 0, "summaryPresent": True,
            })
            self.assertEqual(report["failure"]["reason"], "test command ran zero non-ignored tests")
            self.assertEqual(len(calls), 4)

    def test_cleanup_refuses_replaced_workspace_and_preserves_replacement(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cargo_home = root / "cargo"
            rustup_home = root / "rustup"
            cargo_home.mkdir()
            rustup_home.mkdir()
            tools = {"python": sys.executable, "cargo": "/synthetic/bin/cargo",
                     "rustc": "/synthetic/bin/rustc", "cargoHome": str(cargo_home),
                     "rustupHome": str(rustup_home)}
            workspace = []
            swapped = {}
            real_listdir = os.listdir
            summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"

            def fake_run(command, *, env=None, **kwargs):
                workspace.append(Path(env["HOME"]).parent)
                if command[-1] == "--version":
                    return subprocess.CompletedProcess(command, 0, "synthetic version\n", "")
                return subprocess.CompletedProcess(command, 0, summary, "")

            def swapping_listdir(directory):
                if type(directory) is int and not swapped:
                    path = workspace[0]
                    moved = path.with_name(path.name + "-moved")
                    path.rename(moved)
                    path.mkdir(mode=0o700)
                    sentinel = path / "outside-sentinel.txt"
                    sentinel.write_text("preserve replacement contents\n")
                    swapped.update({"path": path, "moved": moved, "sentinel": sentinel})
                return real_listdir(directory)

            with (
                patch.object(runner, "ROOT", root),
                patch.object(runner, "_resolve_scope_tools", return_value=tools),
                patch.object(runner, "run_owned", side_effect=fake_run),
                patch.object(runner.os, "listdir", side_effect=swapping_listdir),
                patch.object(sys, "argv", ["check.py", "--scope", "host"]),
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(runner.main(), 1)

            try:
                report_path = next((root / "artifacts/scoped-checks").glob("host-*/report.json"))
                report = json.loads(report_path.read_text())
                self.assertTrue(swapped)
                self.assertEqual(len(report["commands"]), 5)
                self.assertFalse(report["regressionsPassed"])
                self.assertFalse(report["complete"])
                self.assertTrue(report["executionWorkspaceRetained"])
                self.assertFalse(report["executionWorkspaceCleanupPassed"])
                self.assertEqual(report["failure"]["stage"], "cleanup")
                self.assertEqual(swapped["sentinel"].read_text(), "preserve replacement contents\n")
                self.assertTrue(swapped["moved"].is_dir())
                self.assertEqual(list(swapped["moved"].iterdir()), [])
                self.assertTrue(all(row["testCounts"]["executed"] == 1
                                    for row in report["commands"]))
            finally:
                if swapped:
                    shutil.rmtree(swapped["path"])
                    shutil.rmtree(swapped["moved"])

    def test_bun_summary_counts_include_stderr_and_exclude_ignored(self):
        counts = runner._test_counts(
            "bun", "", "22 pass\n0 fail\nRan 22 tests across 2 files. [47.00ms]\n",
        )
        self.assertEqual(counts, {"executed": 22, "passed": 22, "failed": 0,
                                  "ignored": 0, "summaryPresent": True})
        ignored = runner._test_counts(
            "bun", "", "0 pass\n0 fail\n2 skip\nRan 2 tests across 1 file. [1.00ms]\n",
        )
        self.assertEqual(ignored["executed"], 0)
        self.assertEqual(ignored["ignored"], 2)
        self.assertTrue(ignored["summaryPresent"])

    def test_web_astro_dependency_preflight_fails_without_running_checks_or_installing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            web_root = root / "remote-web"
            web_root.mkdir()
            tools = {"python": sys.executable, "bun": "/synthetic/bin/bun",
                     "node": "/synthetic/bin/node", "astro": "/synthetic/astro.mjs",
                     "astroAvailable": True, "astroCheckEntry": None,
                     "astroTypescriptEntry": None, "webRoot": str(web_root)}
            calls = []
            environments = []

            def fake_run(command, *, env=None, **kwargs):
                calls.append(command)
                environments.append(env)
                if Path(command[0]).name == "bun":
                    self.assertIn("--no-install", command)
                    self.assertIn("--no-env-file", command)
                    return subprocess.CompletedProcess(command, 0, "1.4.2\n", "")
                if command[-1] == "--version":
                    return subprocess.CompletedProcess(command, 0, "v22.23.3\n", "")
                return subprocess.CompletedProcess(command, 1, "", "missing local check dependency")

            with (
                patch.object(runner, "ROOT", root),
                patch.object(runner, "_resolve_scope_tools", return_value=tools),
                patch.object(runner, "run_owned", side_effect=fake_run),
                patch.object(sys, "argv", ["check.py", "--scope", "web"]),
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(runner.main(), 1)

            report_path = next((root / "artifacts/scoped-checks").glob("web-*/report.json"))
            report = json.loads(report_path.read_text())
            self.assertEqual(report["failure"]["stage"], "preflight")
            self.assertEqual(report["failure"]["name"], "astro-check-dependencies")
            self.assertFalse(report["regressionsPassed"])
            self.assertEqual(report["completedChecks"], 0)
            self.assertFalse(any("test" in command for command in calls))
            self.assertIn("-e", calls[-1])
            self.assertTrue(all(env["CI"] == "true" and env["TERM"] == "dumb"
                                and env["npm_config_yes"] == "false"
                                and env["BUN_CONFIG_NO_INSTALL"] == "1"
                                for env in environments))


if __name__ == "__main__":
    unittest.main()
