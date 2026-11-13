import importlib.util
import json
import ssl
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path


SCRIPT = Path(__file__).with_name("e2e-readiness.py")
SPEC = importlib.util.spec_from_file_location("e2e_readiness", SCRIPT)
e2e = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(e2e)


def completed(argv, payload=None, *, returncode=0, stderr=b""):
    stdout = b"" if payload is None else json.dumps(payload).encode("utf-8")
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class FakeResponse:
    def __init__(self, status):
        self.status = status
        self.closed = False

    def getcode(self):
        return self.status

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return FakeResponse(outcome)


class E2EReadinessTests(unittest.TestCase):
    def test_public_defaults_and_custom_ports_are_canonical(self):
        self.assertEqual(e2e.validate_https_origin(e2e.AUTH_ORIGIN_DEFAULT), e2e.AUTH_ORIGIN_DEFAULT)
        self.assertEqual(e2e.validate_https_origin(e2e.REMOTE_ORIGIN_DEFAULT), e2e.REMOTE_ORIGIN_DEFAULT)
        self.assertEqual(
            e2e.validate_https_origin("https://auth.example.test:8443"),
            "https://auth.example.test:8443",
        )
        self.assertEqual(
            e2e.validate_relay_endpoint(e2e.RELAY_ENDPOINT_DEFAULT),
            (e2e.RELAY_ENDPOINT_DEFAULT, "https://relay.lomi.dev"),
        )
        self.assertEqual(
            e2e.validate_relay_endpoint("wss://relay.example.test:9443/v2/relay"),
            ("wss://relay.example.test:9443/v2/relay", "https://relay.example.test:9443"),
        )

    def test_target_validation_rejects_credentials_paths_and_noncanonical_forms(self):
        for value in (
            "http://auth.example.test",
            "https://user:secret@auth.example.test",
            "https://auth.example.test/path",
            "https://auth.example.test/",
            "https://AUTH.example.test",
            "https://auth.example.test:0443",
            "https://auth.example.test:443",
            "https://auth.example.test?token=secret",
            "https://auth.example.test\n",
        ):
            with self.subTest(value=value):
                self.assertIsNone(e2e.validate_https_origin(value))
        for value in (
            "https://relay.example.test/v2/relay",
            "wss://user:secret@relay.example.test/v2/relay",
            "wss://relay.example.test/v2/relay?ticket=secret",
            "wss://relay.example.test/v1/relay",
            "wss://RELAY.example.test/v2/relay",
        ):
            with self.subTest(value=value):
                self.assertIsNone(e2e.validate_relay_endpoint(value))

    def test_probe_opener_uses_system_tls_without_proxy_or_redirects(self):
        opener = e2e.build_probe_opener()
        proxy_handlers = [handler for handler in opener.handlers if isinstance(handler, e2e.urllib.request.ProxyHandler)]
        redirect = next(handler for handler in opener.handlers if isinstance(handler, e2e.NoRedirectHandler))
        https = next(handler for handler in opener.handlers if isinstance(handler, e2e.urllib.request.HTTPSHandler))
        self.assertTrue(not proxy_handlers or all(handler.proxies == {} for handler in proxy_handlers))
        self.assertIsNone(redirect.redirect_request(None, None, 302, "Found", {}, "https://elsewhere.invalid"))
        self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(https._context.check_hostname)

    def test_probes_use_only_safe_methods_and_classify_routes(self):
        opener = FakeOpener([200, 404, 401, 204, 426])
        result = e2e.probe_endpoints(
            e2e.AUTH_ORIGIN_DEFAULT,
            e2e.REMOTE_ORIGIN_DEFAULT,
            e2e.RELAY_ENDPOINT_DEFAULT,
            opener_factory=lambda: opener,
        )
        self.assertEqual(result["auth_health"]["state"], "healthy")
        self.assertEqual(result["auth_enrollment_route"]["state"], "blocked")
        self.assertEqual(result["auth_enrollment_route"]["code"], "ENROLL_ROUTE_NOT_FOUND")
        self.assertEqual(result["remote_inventory_route"]["state"], "present")
        self.assertEqual(result["relay_health"]["state"], "healthy")
        self.assertEqual(result["relay_route"]["state"], "present")
        expected = [
            ("GET", "https://auth.lomi.dev/health/ready"),
            ("POST", "https://auth.lomi.dev/v2/remote/enrollments"),
            ("GET", "https://remote.lomi.dev/v2/remote/inventory"),
            ("GET", "https://relay.lomi.dev/readyz"),
            ("GET", "https://relay.lomi.dev/v2/relay"),
        ]
        self.assertEqual(
            [(request.get_method(), request.full_url) for request, _ in opener.calls],
            expected,
        )
        self.assertTrue(
            all(
                request.get_header("User-agent") == "Lomi-Remote-E2E-Readiness/1"
                and request.get_header("Accept") == "application/json"
                for request, _ in opener.calls
            )
        )
        self.assertEqual(opener.calls[1][0].data, b"")
        self.assertNotIn("Upgrade", opener.calls[4][0].headers)
        self.assertTrue(all(timeout == e2e.HTTP_TIMEOUT_SECONDS for _, timeout in opener.calls))

    def test_http_403_does_not_confirm_inventory_or_relay_route(self):
        inventory = e2e._http_outcome(403, None, kind="inventory_route")
        relay = e2e._http_outcome(403, None, kind="relay_route")
        self.assertEqual((inventory["state"], inventory["code"]), ("blocked", "INVENTORY_ROUTE_UNCONFIRMED"))
        self.assertEqual((relay["state"], relay["code"]), ("blocked", "RELAY_ROUTE_UNCONFIRMED"))
        self.assertEqual(
            e2e._http_outcome(401, None, kind="inventory_route")["state"],
            "present",
        )

    def test_tls_trust_errors_are_not_reported_as_service_outages(self):
        verification_error = ssl.SSLCertVerificationError("private certificate detail")
        for failure in (verification_error, urllib.error.URLError(verification_error)):
            with self.subTest(failure=type(failure).__name__):
                opener = FakeOpener([failure])
                status, code = e2e.request_status(
                    "https://auth.example.test/health/ready",
                    "GET",
                    opener_factory=lambda: opener,
                )
                result = e2e._http_outcome(status, code, kind="auth_health")
                self.assertEqual(result, {"state": "unknown", "code": "TLS_TRUST_UNAVAILABLE"})
                self.assertNotIn("private certificate detail", json.dumps(result))

    def test_missing_v2_enrollment_route_blocks_overall_readiness(self):
        cli = {
            "version": {"state": "available"},
            "status": {"state": "available"},
            "loginStatus": {"state": "available", "flowState": "ready_to_start"},
            "doctor": {"state": "available", "truncated": False, "blockingFindings": []},
        }
        endpoints = {
            "auth_health": {"state": "healthy"},
            "auth_enrollment_route": {"state": "blocked"},
            "remote_inventory_route": {"state": "present"},
            "relay_health": {"state": "healthy"},
            "relay_route": {"state": "present"},
        }
        self.assertFalse(e2e._ready(cli, endpoints))

    def test_redirect_is_denied_and_location_is_not_reported_or_followed(self):
        secret_location = "https://outside.invalid/path?credential=SECRET"
        request = type("Request", (), {"full_url": "https://auth.example.test/health/ready"})()
        redirect_error = urllib.error.HTTPError(
            request.full_url,
            302,
            "Found",
            {"Location": secret_location},
            None,
        )
        opener = FakeOpener([redirect_error])
        status, error = e2e.request_status(
            request.full_url,
            "GET",
            opener_factory=lambda: opener,
        )
        outcome = e2e._http_outcome(status, error, kind="auth_health")
        self.assertEqual(outcome["state"], "blocked")
        self.assertEqual(outcome["code"], "REDIRECT_DENIED")
        self.assertNotIn("outside.invalid", json.dumps(outcome))
        self.assertEqual(len(opener.calls), 1)

    def test_cli_probes_only_read_commands_and_never_creates_profile(self):
        version = {"programVersion": "1.2.3", "profileSchema": 14}
        response = {"result": {"Ok": {"type": "status", "value": {"hostId": "PRIVATE"}}}}
        login = {
            "result": {
                "Ok": {
                    "type": "loginStatus",
                    "value": {
                        "phase": "idle",
                        "storage": "available",
                        "network": "idle",
                        "locked": False,
                        "pendingCloudRevoke": False,
                        "userCode": "PRIVATE-CODE",
                    },
                }
            }
        }
        doctor = {"report": {"mode": "online", "findings": [], "lastError": None}}
        queued = [version, response, login, doctor]
        invocations = []

        def runner(argv, **kwargs):
            invocations.append((argv, kwargs))
            return completed(argv, queued.pop(0))

        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "not-created-profile"
            result = e2e.probe_cli("/path/to/lomiremote", str(profile), runner=runner)
            self.assertFalse(profile.exists())

        self.assertEqual(result["version"]["state"], "available")
        self.assertEqual(result["status"]["state"], "available")
        self.assertEqual(result["loginStatus"]["flowState"], "ready_to_start")
        self.assertEqual(result["doctor"]["state"], "available")
        self.assertEqual(
            [argv[-2:] for argv, _ in invocations],
            [["version", "--json"], ["status", "--json"], ["status", "--json"], ["doctor", "--json"]],
        )
        self.assertEqual(invocations[2][0][-3:], ["login", "status", "--json"])
        self.assertFalse(any("code" in argv or "start" in argv or "logout" in argv for argv, _ in invocations))
        self.assertTrue(all(kwargs["shell"] is False for _, kwargs in invocations))
        self.assertNotIn("PRIVATE-CODE", json.dumps(result))
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_login_lock_flags_distinguish_authorization_from_credential_lock(self):
        def observe(phase, storage, locked, pending=False):
            document = {
                "result": {
                    "Ok": {
                        "type": "loginStatus",
                        "value": {
                            "phase": phase,
                            "storage": storage,
                            "network": "idle",
                            "locked": locked,
                            "pendingCloudRevoke": pending,
                        },
                    }
                }
            }
            return e2e._login_status_observation(document, 0, None)["flowState"]

        self.assertEqual(observe("idle", "available", True), "ready_to_start")
        self.assertEqual(observe("locked", "available", True), "ready_to_start")
        self.assertEqual(observe("locked", "locked", True), "credential_locked")
        self.assertEqual(observe("ready", "available", True), "authorization_blocked")
        self.assertEqual(observe("idle", "available", True, pending=True), "pending_revoke")

    def test_doctor_findings_gate_readiness_except_restartable_authorization(self):
        endpoints = {
            "auth_health": {"state": "healthy"},
            "auth_enrollment_route": {"state": "present"},
            "remote_inventory_route": {"state": "present"},
            "relay_health": {"state": "healthy"},
            "relay_route": {"state": "present"},
        }
        cli = {
            "version": {"state": "available"},
            "status": {"state": "available"},
            "loginStatus": {"state": "available", "flowState": "ready_to_start"},
            "doctor": {"state": "available", "truncated": False, "blockingFindings": []},
        }
        self.assertTrue(e2e._ready(cli, endpoints))

        for check, state in (
            ("ProfileOwner", "PermissionDenied"),
            ("RootPermissions", "Invalid"),
            ("Shell", "Unavailable"),
            ("Storage", "Unavailable"),
            ("Clock", "ConfigurationInvalid"),
            ("Network", "Unknown"),
        ):
            with self.subTest(check=check, state=state):
                cli["doctor"]["blockingFindings"] = [{"check": check, "state": state}]
                self.assertFalse(e2e._ready(cli, endpoints))

        cli["doctor"]["blockingFindings"] = [
            {"check": "Authorization", "state": "AuthorizationRejected"}
        ]
        self.assertTrue(e2e._ready(cli, endpoints))
        cli["loginStatus"]["flowState"] = "authenticated"
        self.assertFalse(e2e._ready(cli, endpoints))
        cli["loginStatus"]["flowState"] = "authorization_blocked"
        cli["doctor"]["blockingFindings"] = []
        self.assertFalse(e2e._ready(cli, endpoints))
        cli["loginStatus"]["flowState"] = "credential_locked"
        self.assertFalse(e2e._ready(cli, endpoints))

        cli["loginStatus"]["flowState"] = "ready_to_start"
        cli["doctor"]["truncated"] = True
        self.assertFalse(e2e._ready(cli, endpoints))

    def test_real_host_prelogin_and_expired_network_observations_allow_manual_testing(self):
        endpoints = {
            "auth_health": {"state": "healthy"},
            "auth_enrollment_route": {"state": "present"},
            "remote_inventory_route": {"state": "present"},
            "relay_health": {"state": "healthy"},
            "relay_route": {"state": "present"},
        }
        for phase, network in [("idle", "idle"), ("awaitingApproval", "working"), ("ready", "available")]:
            with self.subTest(phase=phase):
                login = e2e._login_status_observation({"result": {"Ok": {
                    "type": "loginStatus", "value": {
                        "phase": phase, "storage": "available", "network": network,
                        "locked": phase != "ready", "pendingCloudRevoke": False,
                    },
                }}}, 0, None)
                findings = [
                    {"check": check, "state": "Healthy"}
                    for check in ["ProfileOwner", "IpcVersion", "Clock", "RootPermissions", "Shell", "Storage"]
                ] + [
                    {"check": "Dns", "state": "Unknown"},
                    {"check": "Tls", "state": "Unknown"},
                    {"check": "Proxy", "state": "DisabledByPolicy"},
                    {"check": "Network", "state": "Healthy" if phase == "ready" else "Unknown"},
                    {"check": "Authorization", "state": "Healthy" if phase == "ready" else "Unknown"},
                ]
                cli = {
                    "version": {"state": "available"}, "status": {"state": "available"},
                    "loginStatus": login,
                    "doctor": e2e._doctor_observation({"report": {"mode": "online", "findings": findings}}, 0, None),
                }
                self.assertTrue(e2e._ready(cli, endpoints))
                findings.append({"check": "Tls", "state": "TransportUnavailable"})
                cli["doctor"] = e2e._doctor_observation({"report": {"mode": "online", "findings": findings}}, 0, None)
                self.assertFalse(e2e._ready(cli, endpoints))

    def test_nonzero_permission_denial_stays_unknown_and_does_not_echo_output(self):
        secret = b"SECRET-CREDENTIALS-AND-PROFILE-PATH"
        invocations = []

        def runner(argv, **kwargs):
            invocations.append(argv)
            if argv[-2:] == ["version", "--json"]:
                return completed(argv, {"programVersion": "1.2.3", "profileSchema": 14})
            return subprocess.CompletedProcess(
                argv,
                5,
                json.dumps({"error": {"code": "LOCAL_PERMISSION_DENIED"}}).encode(),
                secret,
            )

        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "not-created-profile"
            result = e2e.probe_cli("lomiremote", str(profile), runner=runner)
            self.assertFalse(profile.exists())
        self.assertEqual(result["status"], {"state": "unknown", "code": "LOCAL_PERMISSION_DENIED"})
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("private/profile", json.dumps(result))

    def test_ipc_permission_error_is_a_closed_unknown_state(self):
        def runner(argv, **kwargs):
            if argv[-2:] == ["version", "--json"]:
                return completed(argv, {"programVersion": "1.2.3", "profileSchema": 14})
            return completed(
                argv,
                {"result": {"Err": "PERMISSION_DENIED"}},
                returncode=5,
            )

        result = e2e.probe_cli("lomiremote", "/private/profile", runner=runner)
        self.assertEqual(result["status"], {"state": "unknown", "code": "PERMISSION_DENIED"})
        self.assertNotIn("absent", json.dumps(result))

    def test_malformed_cli_json_is_closed_and_never_echoed(self):
        secret = b"https://example.invalid/?token=SECRET-CODE"

        def runner(argv, **kwargs):
            if argv[-2:] == ["version", "--json"]:
                return completed(argv, {"programVersion": "1.2.3", "profileSchema": 14})
            return subprocess.CompletedProcess(argv, 0, secret, b"PRIVATE STDERR")

        result = e2e.probe_cli("lomiremote", None, runner=runner)
        self.assertEqual(result["loginStatus"], {"state": "unknown", "code": "CLI_JSON_INVALID"})
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("PRIVATE STDERR", json.dumps(result))

    def test_missing_binary_is_unknown_not_profile_absent(self):
        def runner(argv, **kwargs):
            raise FileNotFoundError("/private/path/with/secrets")

        result = e2e.probe_cli("/private/path/with/secrets", None, runner=runner)
        self.assertEqual(result["version"]["state"], "unknown")
        self.assertEqual(result["status"]["state"], "unknown")
        self.assertNotIn("absent", json.dumps(result))
        self.assertNotIn("private/path", json.dumps(result))

    def test_diagnostic_counts_and_codes_are_closed(self):
        document = {
            "report": {
                "mode": "online",
                "findings": [
                    {"check": "Service", "state": "Healthy", "guidance": "SECRET"},
                    {"check": "ProfileOwner", "state": "PermissionDenied"},
                    {"check": "Network", "state": "Unknown"},
                    {"check": "Proxy", "state": "DisabledByPolicy"},
                ],
                "lastError": "networkUnavailable",
                "truncated": False,
            }
        }
        result = e2e._doctor_observation(document, 0, None)
        self.assertEqual(
            result["healthCounts"],
            {"healthy": 1, "unavailable": 0, "blocked": 1, "unknown": 1, "policy": 1},
        )
        self.assertEqual(result["lastError"], "networkUnavailable")
        self.assertEqual(
            result["blockingFindings"],
            [
                {"check": "ProfileOwner", "state": "PermissionDenied"},
                {"check": "Network", "state": "Unknown"},
            ],
        )
        self.assertNotIn("SECRET", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
