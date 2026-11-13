#!/usr/bin/env python3
"""Read-only readiness probes for a manually completed CLI and phone login."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Callable
from urllib.parse import urlsplit

AUTH_ORIGIN_DEFAULT = "https://auth.lomi.dev"
REMOTE_ORIGIN_DEFAULT = "https://remote.lomi.dev"
RELAY_ENDPOINT_DEFAULT = "wss://relay.lomi.dev/v2/relay"

CLI_TIMEOUT_SECONDS = 5
HTTP_TIMEOUT_SECONDS = 4
MAX_CLI_OUTPUT_BYTES = 1024 * 1024

EXIT_READY = 0
EXIT_BLOCKED = 3

SUPPORTED_CLI_CODES = {
    "DAEMON_UNAVAILABLE",
    "LOCAL_PERMISSION_DENIED",
    "INVALID_LOCAL_PROFILE",
    "LOCAL_HOST_IDENTITY_CHANGED",
    "UPDATE_REQUIRED",
    "DOCTOR_RESPONSE_INVALID",
    "DOCTOR_REQUEST_UNAVAILABLE",
    "NONROOT_HOST_ACCOUNT_REQUIRED",
    "PROFILE_DIRECTORY_REQUIRED",
    "INVALID_ARGUMENT",
    "UNSUPPORTED_LOCAL_OPERATION",
    "LOCAL_REQUEST_REJECTED",
    "UNAVAILABLE",
    "PERMISSION_DENIED",
    "INVALID_ARGUMENT",
    "VERSION_MISMATCH",
    "CONFLICT",
    "QUARANTINE",
}

AUTH_PHASES = {
    "unconfigured",
    "idle",
    "initializing",
    "awaitingApproval",
    "exchanging",
    "registering",
    "ready",
    "refreshing",
    "locked",
    "pendingRevoke",
    "unavailable",
}
AUTH_STORAGES = {"unconfigured", "available", "locked", "unavailable"}
AUTH_NETWORKS = {"idle", "working", "available", "unavailable"}
DOCTOR_MODES = {"online", "offline"}
DOCTOR_STATES = {
    "Healthy",
    "Unavailable",
    "PermissionDenied",
    "Incompatible",
    "Unknown",
    "NotObserved",
    "ConfigurationInvalid",
    "TransportUnavailable",
    "AuthorizationRejected",
    "Invalid",
    "DisabledByPolicy",
}
DOCTOR_CHECKS = {
    "IpcVersion",
    "ProfileOwner",
    "Service",
    "Autostart",
    "Clock",
    "Network",
    "Dns",
    "Tls",
    "Proxy",
    "Authorization",
    "Storage",
    "Shell",
    "RemoteGit",
    "NativeGit",
    "RootPermissions",
    "Limits",
    "ActivationJournal",
}
DOCTOR_READINESS_CHECKS = {
    "IpcVersion",
    "ProfileOwner",
    "Service",
    "Clock",
    "Network",
    "Dns",
    "Tls",
    "Proxy",
    "Authorization",
    "Storage",
    "Shell",
    "RootPermissions",
}
DIAGNOSTIC_CODES = {
    "hostStarted",
    "hostStartRejected",
    "ipcRequestRejected",
    "ipcVersionMismatch",
    "profileInvalid",
    "serviceUnavailable",
    "serviceRegistrationMissing",
    "authenticationConfigurationMissing",
    "authenticationRejected",
    "networkUnavailable",
    "networkConfigurationInvalid",
    "dnsUnavailable",
    "tlsUnavailable",
    "networkTimeout",
    "storageUnavailable",
    "shellConfigurationMissing",
    "shellExecutableUnavailable",
    "builtInGitUnavailable",
    "nativeGitUnavailable",
    "activationPending",
    "resourceLimitReached",
}

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep probes on the exact operator-supplied origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _has_controls_or_whitespace(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F or character.isspace() for character in value)


def _canonical_host(host: str) -> bool:
    if not host or host != host.lower() or not host.isascii() or host.endswith("."):
        return False
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        address = None
    if address is not None:
        return str(address) == host
    if len(host) > 253:
        return False
    labels = host.split(".")
    if not all(_DNS_LABEL.fullmatch(label) for label in labels):
        return False
    last = labels[-1]
    numeric_or_hex = last.isdigit() or (last.startswith("0x") and all(c in "0123456789abcdef" for c in last[2:]))
    # Avoid URL parser interpretations that treat numeric-looking DNS names as IPs.
    return not numeric_or_hex


def _parse_canonical_endpoint(value: str, scheme: str, path: str) -> tuple[str, str] | None:
    max_length = 189 if scheme == "wss" else 180
    if not isinstance(value, str) or not value or len(value) > max_length or _has_controls_or_whitespace(value):
        return None
    if not value.isascii():
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != scheme
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
        or parsed.query
        or parsed.fragment
        or parsed.path != path
    ):
        return None
    host = parsed.hostname
    if host is None or not _canonical_host(host):
        return None
    authority = host
    if port is not None:
        if not 1 <= port <= 65535 or port == (443 if scheme in {"https", "wss"} else None):
            return None
        raw_port = parsed.netloc.rsplit(":", 1)[-1]
        if raw_port != str(port):
            return None
        authority += f":{port}"
    if parsed.netloc != authority:
        return None
    canonical = f"{scheme}://{authority}{path}"
    if value != canonical:
        return None
    return canonical, authority


def validate_https_origin(value: str) -> str | None:
    """Return a canonical HTTPS origin or None; credentials and paths are rejected."""
    result = _parse_canonical_endpoint(value, "https", "")
    return result[0] if result is not None else None


def validate_relay_endpoint(value: str) -> tuple[str, str] | None:
    """Return the canonical WSS endpoint and its HTTPS probe origin."""
    result = _parse_canonical_endpoint(value, "wss", "/v2/relay")
    if result is None:
        return None
    endpoint, authority = result
    return endpoint, f"https://{authority}"


def build_probe_opener() -> urllib.request.OpenerDirector:
    """Use system trust roots, no environment proxy, and no redirects."""
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    )


def request_status(
    url: str,
    method: str,
    *,
    timeout: float = HTTP_TIMEOUT_SECONDS,
    opener_factory: Callable[[], Any] = build_probe_opener,
) -> tuple[int | None, str | None]:
    """Issue one bounded request and return only an HTTP status or closed failure."""
    data = b"" if method == "POST" else None
    headers = {
        "User-Agent": "Lomi-Remote-E2E-Readiness/1",
        "Accept": "application/json",
    }
    if method == "POST":
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        response = opener_factory().open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        return status, None
    except ssl.SSLCertVerificationError:
        return None, "TLS_TRUST_UNAVAILABLE"
    except ssl.SSLError:
        return None, "TLS_UNAVAILABLE"
    except urllib.error.URLError as error:
        reason = error.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            return None, "TLS_TRUST_UNAVAILABLE"
        if isinstance(reason, ssl.SSLError):
            return None, "TLS_UNAVAILABLE"
        return None, "TRANSPORT_UNAVAILABLE"
    except Exception:
        return None, "TRANSPORT_UNAVAILABLE"
    try:
        return response.getcode(), None
    except Exception:
        return None, "TRANSPORT_UNAVAILABLE"
    finally:
        try:
            response.close()
        except Exception:
            pass


def _http_outcome(
    status: int | None,
    error_code: str | None,
    *,
    kind: str,
) -> dict[str, Any]:
    if error_code is not None or status is None:
        code = error_code if error_code in {
            "TLS_TRUST_UNAVAILABLE",
            "TLS_UNAVAILABLE",
            "TRANSPORT_UNAVAILABLE",
        } else "TRANSPORT_UNAVAILABLE"
        return {"state": "unknown", "code": code}
    result: dict[str, Any] = {"httpStatus": status}
    if 300 <= status < 400:
        return {**result, "state": "blocked", "code": "REDIRECT_DENIED"}
    if kind == "auth_health":
        if status in {200, 204}:
            return {**result, "state": "healthy", "code": "HTTP_HEALTHY"}
        if status == 404:
            return {**result, "state": "blocked", "code": "AUTH_HEALTH_NOT_FOUND"}
    elif kind == "enrollment_route":
        if status in {400, 422}:
            return {**result, "state": "present", "code": "ROUTE_VALIDATION_REJECTED_EMPTY_BODY"}
        if status == 404:
            return {**result, "state": "blocked", "code": "ENROLL_ROUTE_NOT_FOUND"}
        if 200 <= status < 300:
            return {**result, "state": "blocked", "code": "UNEXPECTED_EMPTY_BODY_SUCCESS"}
    elif kind == "inventory_route":
        if status == 401:
            return {**result, "state": "present", "code": "ROUTE_REQUIRES_AUTHENTICATION"}
        if status == 403:
            return {**result, "state": "blocked", "code": "INVENTORY_ROUTE_UNCONFIRMED"}
        if status == 404:
            return {**result, "state": "missing", "code": "REMOTE_INVENTORY_NOT_FOUND"}
        if 200 <= status < 300:
            return {**result, "state": "blocked", "code": "UNEXPECTED_PUBLIC_INVENTORY_RESPONSE"}
    elif kind == "relay_health":
        if status in {200, 204}:
            return {**result, "state": "healthy", "code": "HTTP_HEALTHY"}
        if status == 404:
            return {**result, "state": "missing", "code": "RELAY_HEALTH_NOT_FOUND"}
    elif kind == "relay_route":
        if status == 404:
            return {**result, "state": "missing", "code": "RELAY_ROUTE_NOT_FOUND"}
        if status == 403:
            return {**result, "state": "blocked", "code": "RELAY_ROUTE_UNCONFIRMED"}
        if status in {200, 201, 202, 204, 400, 401, 426}:
            return {**result, "state": "present", "code": "PLAIN_GET_ROUTE_PRESENT"}
    if status in {408, 429} or status >= 500:
        return {**result, "state": "unknown", "code": "HTTP_SERVICE_UNAVAILABLE"}
    return {**result, "state": "blocked", "code": "UNEXPECTED_HTTP_STATUS"}


def probe_endpoints(
    auth_origin: str,
    remote_origin: str,
    relay_endpoint: str,
    *,
    opener_factory: Callable[[], Any] = build_probe_opener,
    timeout: float = HTTP_TIMEOUT_SECONDS,
) -> dict[str, dict[str, Any]]:
    """Probe only public health and route-presence surfaces with safe methods."""
    if validate_https_origin(auth_origin) != auth_origin or validate_https_origin(remote_origin) != remote_origin:
        raise ValueError("INVALID_TARGET_ORIGIN")
    relay = validate_relay_endpoint(relay_endpoint)
    if relay is None:
        raise ValueError("INVALID_RELAY_ENDPOINT")
    _, relay_probe_origin = relay
    probes = (
        ("auth_health", f"{auth_origin}/health/ready", "GET", "auth_health"),
        ("auth_enrollment_route", f"{auth_origin}/v2/remote/enrollments", "POST", "enrollment_route"),
        ("remote_inventory_route", f"{remote_origin}/v2/remote/inventory", "GET", "inventory_route"),
        ("relay_health", f"{relay_probe_origin}/readyz", "GET", "relay_health"),
        ("relay_route", f"{relay_probe_origin}/v2/relay", "GET", "relay_route"),
    )
    results: dict[str, dict[str, Any]] = {}
    for name, url, method, kind in probes:
        status, error = request_status(
            url,
            method,
            timeout=timeout,
            opener_factory=opener_factory,
        )
        results[name] = _http_outcome(status, error, kind=kind)
    return results


def _decode_json_output(stdout: bytes) -> dict[str, Any] | None:
    if not isinstance(stdout, bytes) or len(stdout) > MAX_CLI_OUTPUT_BYTES:
        return None
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _closed_cli_code(value: Any) -> str:
    return value if isinstance(value, str) and value in SUPPORTED_CLI_CODES else "CLI_REPORTED_ERROR"


def _response_result(document: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    result = document.get("result")
    if not isinstance(result, dict):
        return None, "CLI_RESPONSE_INVALID"
    if isinstance(result.get("Ok"), dict):
        return result["Ok"], None
    if "Err" in result:
        return None, _closed_cli_code(result.get("Err"))
    return None, "CLI_RESPONSE_INVALID"


def _top_level_failure(document: dict[str, Any] | None) -> str | None:
    if not isinstance(document, dict):
        return None
    error = document.get("error")
    if isinstance(error, dict) and "code" in error:
        return _closed_cli_code(error.get("code"))
    result = document.get("result")
    if isinstance(result, dict) and "Err" in result:
        return _closed_cli_code(result.get("Err"))
    return None


def _invoke_cli(
    binary: str,
    profile_dir: str | None,
    args: list[str],
    *,
    runner: Callable[..., Any] = subprocess.run,
) -> tuple[Any | None, str | None]:
    argv = [binary]
    if profile_dir is not None:
        argv.extend(["--profile-dir", profile_dir])
    argv.extend(args)
    try:
        completed = runner(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=CLI_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return None, "CLI_TIMEOUT"
    except Exception:
        return None, "CLI_UNAVAILABLE"
    if not isinstance(getattr(completed, "stdout", None), bytes):
        return completed, "CLI_OUTPUT_INVALID"
    if len(completed.stdout) > MAX_CLI_OUTPUT_BYTES:
        return completed, "CLI_OUTPUT_TOO_LARGE"
    return completed, None


def _version_observation(document: dict[str, Any] | None, returncode: int | None, code: str | None) -> dict[str, Any]:
    if code is not None or document is None or returncode != 0:
        return {"state": "unknown", "code": code or _top_level_failure(document) or "CLI_VERSION_UNAVAILABLE"}
    version = document.get("programVersion")
    schema = document.get("profileSchema")
    if not isinstance(version, str) or not _VERSION.fullmatch(version) or not isinstance(schema, int) or isinstance(schema, bool):
        return {"state": "unknown", "code": "CLI_RESPONSE_INVALID"}
    return {"state": "available", "programVersion": version, "profileSchema": schema}


def _simple_response_observation(
    document: dict[str, Any] | None,
    returncode: int | None,
    code: str | None,
    expected_type: str,
) -> dict[str, Any]:
    if code is not None or document is None:
        return {"state": "unknown", "code": code or "CLI_JSON_INVALID"}
    if returncode != 0:
        return {"state": "unknown", "code": _top_level_failure(document) or "CLI_COMMAND_FAILED"}
    value, error = _response_result(document)
    if error is not None:
        return {"state": "unknown", "code": error}
    if not isinstance(value, dict) or value.get("type") != expected_type:
        return {"state": "unknown", "code": "CLI_RESPONSE_INVALID"}
    return {"state": "available"}


def _login_status_observation(
    document: dict[str, Any] | None,
    returncode: int | None,
    code: str | None,
) -> dict[str, Any]:
    if code is not None or document is None:
        return {"state": "unknown", "code": code or "CLI_JSON_INVALID"}
    if returncode != 0:
        return {"state": "unknown", "code": _top_level_failure(document) or "CLI_COMMAND_FAILED"}
    value, error = _response_result(document)
    if error is not None:
        return {"state": "unknown", "code": error}
    if not isinstance(value, dict) or value.get("type") != "loginStatus":
        return {"state": "unknown", "code": "CLI_RESPONSE_INVALID"}
    status = value.get("value")
    if not isinstance(status, dict):
        return {"state": "unknown", "code": "CLI_RESPONSE_INVALID"}
    phase = status.get("phase")
    storage = status.get("storage")
    network = status.get("network")
    locked = status.get("locked")
    pending_revoke = status.get("pendingCloudRevoke")
    if (
        not isinstance(phase, str)
        or phase not in AUTH_PHASES
        or not isinstance(storage, str)
        or storage not in AUTH_STORAGES
        or not isinstance(network, str)
        or network not in AUTH_NETWORKS
        or not isinstance(locked, bool)
        or not isinstance(pending_revoke, bool)
    ):
        return {"state": "unknown", "code": "CLI_RESPONSE_INVALID"}
    if pending_revoke or phase == "pendingRevoke":
        flow_state = "pending_revoke"
    elif storage == "locked":
        flow_state = "credential_locked"
    elif phase == "unconfigured" or storage == "unconfigured":
        flow_state = "not_configured"
    elif phase == "unavailable" or storage == "unavailable" or network == "unavailable":
        flow_state = "unavailable"
    elif phase == "ready":
        flow_state = "authorization_blocked" if locked else "authenticated"
    elif phase in {"idle", "locked"}:
        flow_state = "ready_to_start"
    else:
        flow_state = "in_progress"
    return {
        "state": "available",
        "phase": phase,
        "storage": storage,
        "network": network,
        "locked": locked,
        "pendingCloudRevoke": pending_revoke,
        "flowState": flow_state,
    }


def _doctor_observation(
    document: dict[str, Any] | None,
    returncode: int | None,
    code: str | None,
) -> dict[str, Any]:
    if code is not None or document is None:
        return {
            "state": "unknown",
            "code": code or "CLI_JSON_INVALID",
            "healthCounts": _empty_health_counts(),
            "blockingFindings": [],
        }
    report = document.get("report")
    if not isinstance(report, dict):
        return {
            "state": "unknown",
            "code": _top_level_failure(document) or "CLI_RESPONSE_INVALID",
            "healthCounts": _empty_health_counts(),
            "blockingFindings": [],
        }
    mode = report.get("mode")
    findings = report.get("findings")
    if (
        not isinstance(mode, str)
        or mode not in DOCTOR_MODES
        or not isinstance(findings, list)
        or len(findings) > 32
    ):
        return {
            "state": "unknown",
            "code": "CLI_RESPONSE_INVALID",
            "healthCounts": _empty_health_counts(),
            "blockingFindings": [],
        }
    truncated = report.get("truncated", False)
    if not isinstance(truncated, bool):
        return {
            "state": "unknown",
            "code": "CLI_RESPONSE_INVALID",
            "healthCounts": _empty_health_counts(),
            "blockingFindings": [],
        }
    counts = _empty_health_counts()
    blocking_findings = []
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or not isinstance(finding.get("check"), str)
            or finding.get("check") not in DOCTOR_CHECKS
            or not isinstance(finding.get("state"), str)
            or finding.get("state") not in DOCTOR_STATES
        ):
            return {
                "state": "unknown",
                "code": "CLI_RESPONSE_INVALID",
                "healthCounts": _empty_health_counts(),
                "blockingFindings": [],
            }
        check = finding["check"]
        state = finding["state"]
        if state == "Healthy":
            counts["healthy"] += 1
        elif state in {"Unavailable", "TransportUnavailable"}:
            counts["unavailable"] += 1
        elif state in {"PermissionDenied", "Incompatible", "ConfigurationInvalid", "AuthorizationRejected", "Invalid"}:
            counts["blocked"] += 1
        elif state == "DisabledByPolicy":
            counts["policy"] += 1
        else:
            counts["unknown"] += 1
        if check in DOCTOR_READINESS_CHECKS and not (
            state == "Healthy" or (check == "Proxy" and state == "DisabledByPolicy")
        ):
            blocking_findings.append({"check": check, "state": state})
    last_error = report.get("lastError")
    if last_error is not None and (
        not isinstance(last_error, str) or last_error not in DIAGNOSTIC_CODES
    ):
        last_error = None
    if mode == "online" and returncode == 0:
        return {
            "state": "available",
            "mode": mode,
            "healthCounts": counts,
            "blockingFindings": blocking_findings,
            "truncated": truncated,
            "lastError": last_error,
        }
    return {
        "state": "unknown",
        "mode": mode,
        "healthCounts": counts,
        "blockingFindings": blocking_findings,
        "truncated": truncated,
        "lastError": last_error,
        "code": "DOCTOR_OFFLINE",
    }


def _empty_health_counts() -> dict[str, int]:
    return {"healthy": 0, "unavailable": 0, "blocked": 0, "unknown": 0, "policy": 0}


def probe_cli(
    binary: str,
    profile_dir: str | None,
    *,
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Read CLI version, Host status, login status, and redacted doctor output."""
    completed, invoke_error = _invoke_cli(binary, None, ["version", "--json"], runner=runner)
    version_document = _decode_json_output(completed.stdout) if completed is not None and invoke_error is None else None
    version = _version_observation(
        version_document,
        getattr(completed, "returncode", None),
        invoke_error,
    )
    result: dict[str, Any] = {
        "version": version,
        "status": {"state": "unknown", "code": "CLI_UNAVAILABLE"},
        "loginStatus": {"state": "unknown", "code": "CLI_UNAVAILABLE"},
        "doctor": {
            "state": "unknown",
            "code": "CLI_UNAVAILABLE",
            "healthCounts": _empty_health_counts(),
            "blockingFindings": [],
        },
    }
    if version["state"] != "available":
        return result

    commands = (
        ("status", ["status", "--json"], lambda doc, rc, code: _simple_response_observation(doc, rc, code, "status")),
        ("loginStatus", ["login", "status", "--json"], _login_status_observation),
        ("doctor", ["doctor", "--json"], _doctor_observation),
    )
    for name, args, summarize in commands:
        completed, invoke_error = _invoke_cli(binary, profile_dir, args, runner=runner)
        document = _decode_json_output(completed.stdout) if completed is not None and invoke_error is None else None
        result[name] = summarize(document, getattr(completed, "returncode", None), invoke_error)
    return result


def _ready(cli: dict[str, Any], endpoints: dict[str, dict[str, Any]]) -> bool:
    if cli.get("version", {}).get("state") != "available":
        return False
    if cli.get("status", {}).get("state") != "available":
        return False
    login = cli.get("loginStatus", {})
    if login.get("state") != "available" or login.get("flowState") not in {
        "ready_to_start",
        "in_progress",
        "authenticated",
    }:
        return False
    doctor = cli.get("doctor", {})
    if doctor.get("state") != "available" or doctor.get("truncated") is not False:
        return False
    blocking_findings = doctor.get("blockingFindings")
    if not isinstance(blocking_findings, list):
        return False
    for finding in blocking_findings:
        if not isinstance(finding, dict):
            return False
        check, state = finding.get("check"), finding.get("state")
        # These are historical observations, not fresh connection failures.
        # The Host expires DNS/TLS evidence after 60 seconds without HTTPS.
        if check in {"Dns", "Tls", "Proxy"} and state in {"Unknown", "NotObserved"}:
            continue
        if (
            check == "Network"
            and state in {"Unknown", "NotObserved"}
            and login.get("network") in {"idle", "working", "available"}
        ):
            continue
        if (
            check == "Authorization"
            and state in {"Unknown", "NotObserved"}
            and login.get("flowState") in {"ready_to_start", "in_progress"}
        ):
            continue
        if (
            finding == {"check": "Authorization", "state": "AuthorizationRejected"}
            and login.get("flowState") == "ready_to_start"
        ):
            continue
        return False
    expected = {
        "auth_health": "healthy",
        "auth_enrollment_route": "present",
        "remote_inventory_route": "present",
        "relay_health": "healthy",
        "relay_route": "present",
    }
    return all(endpoints.get(name, {}).get("state") == state for name, state in expected.items())


def _diagnostic_codes(cli: dict[str, Any], endpoints: dict[str, dict[str, Any]]) -> list[str]:
    codes = set()
    for observation in cli.values():
        if isinstance(observation, dict):
            code = observation.get("code")
            if isinstance(code, str) and code in SUPPORTED_CLI_CODES | {
                "CLI_TIMEOUT",
                "CLI_UNAVAILABLE",
                "CLI_OUTPUT_INVALID",
                "CLI_OUTPUT_TOO_LARGE",
                "CLI_JSON_INVALID",
                "CLI_RESPONSE_INVALID",
                "CLI_VERSION_UNAVAILABLE",
                "CLI_COMMAND_FAILED",
                "DOCTOR_OFFLINE",
            }:
                codes.add(code)
            last_error = observation.get("lastError")
            if isinstance(last_error, str) and last_error in DIAGNOSTIC_CODES:
                codes.add(last_error)
    for observation in endpoints.values():
        code = observation.get("code")
        if isinstance(code, str):
            codes.add(code)
    return sorted(codes)


def collect_readiness(
    binary: str,
    profile_dir: str | None,
    auth_origin: str,
    remote_origin: str,
    relay_endpoint: str,
    *,
    runner: Callable[..., Any] = subprocess.run,
    opener_factory: Callable[[], Any] = build_probe_opener,
) -> dict[str, Any]:
    auth = validate_https_origin(auth_origin)
    remote = validate_https_origin(remote_origin)
    relay = validate_relay_endpoint(relay_endpoint)
    if auth is None or remote is None or relay is None:
        return {
            "state": "blocked",
            "code": "INVALID_TARGET_ORIGIN",
            "manualValidationRequired": True,
            "cli": {},
            "endpoints": {},
            "diagnosticCodes": ["INVALID_TARGET_ORIGIN"],
        }
    cli = probe_cli(binary, profile_dir, runner=runner)
    endpoints = probe_endpoints(auth, remote, relay_endpoint, opener_factory=opener_factory)
    ready = _ready(cli, endpoints)
    return {
        "state": "prerequisites_present" if ready else "blocked",
        "manualValidationRequired": True,
        "cli": cli,
        "endpoints": endpoints,
        "diagnosticCodes": _diagnostic_codes(cli, endpoints),
    }


def _print_summary(result: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        json.dump(result, sys.stdout, separators=(",", ":"), sort_keys=True)
        sys.stdout.write("\n")
        return
    print(f"E2E readiness: {result['state']}")
    for name, observation in result.get("cli", {}).items():
        if name == "version" and observation.get("state") == "available":
            print(f"CLI {name}: available ({observation['programVersion']})")
        elif name == "doctor" and "mode" in observation:
            print(f"CLI {name}: {observation['mode']}")
        else:
            print(f"CLI {name}: {observation.get('state', 'unknown')}")
    for name, observation in result.get("endpoints", {}).items():
        status = observation.get("httpStatus")
        suffix = f" (HTTP {status})" if isinstance(status, int) else ""
        print(f"Endpoint {name}: {observation['state']}{suffix}")
    print("Manual CLI login and phone validation are required; this probe does not complete E2E.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, metavar="PATH", help="lomiremote executable")
    parser.add_argument("--profile-dir", metavar="PATH", help="read this existing local Host profile")
    parser.add_argument("--auth-origin", default=AUTH_ORIGIN_DEFAULT, metavar="HTTPS_ORIGIN")
    parser.add_argument("--remote-origin", default=REMOTE_ORIGIN_DEFAULT, metavar="HTTPS_ORIGIN")
    parser.add_argument("--relay-origin", default=RELAY_ENDPOINT_DEFAULT, metavar="WSS_ENDPOINT")
    parser.add_argument("--json", action="store_true", help="write only the closed readiness summary as JSON")
    args = parser.parse_args(argv)

    result = collect_readiness(
        args.binary,
        args.profile_dir,
        args.auth_origin,
        args.remote_origin,
        args.relay_origin,
    )
    _print_summary(result, as_json=args.json)
    return EXIT_READY if result["state"] == "prerequisites_present" else EXIT_BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())
