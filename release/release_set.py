#!/usr/bin/env python3
"""Validate and canonicalize an offline Lomi Remote release-set manifest.

This tool checks recorded release declarations and optional local file/source
mappings. It does not qualify a product, verify signatures, access the network,
publish artifacts, or change Git repositories.
"""

from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import unicodedata
from typing import Any, NoReturn
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "release-set.schema.json"
COMPONENTS = ("host", "api", "identity", "relay", "web", "desktop", "mobile")
RELEASE_SECTIONS = ("compatibility", "database", "update_trust", "qualification")
TARGET_OS_ALIASES = {
    "browser": "web",
    "darwin": "macos",
    "iphoneos": "ios",
    "osx": "macos",
    "win": "windows",
    "win32": "windows",
}
TARGET_ARCHITECTURE_ALIASES = {
    "amd64": "x86_64",
    "arm64": "aarch64",
    "arm64v8a": "arm64-v8a",
    "armv7": "armeabi-v7a",
    "x64": "x86_64",
}
HOST_TARGET_ABIS = {
    ("linux", "aarch64"): "gnu",
    ("linux", "x86_64"): "gnu",
    ("macos", "aarch64"): "darwin",
    ("macos", "x86_64"): "darwin",
    ("windows", "aarch64"): "msvc",
    ("windows", "x86_64"): "msvc",
}
DESKTOP_TARGET_ABIS = {
    ("linux", "x86_64"): "gnu",
    ("macos", "aarch64"): "darwin",
    ("macos", "x86_64"): "darwin",
    ("windows", "x86_64"): "msvc",
}
MOBILE_PACKAGE_ARCHITECTURES = {
    "android": {
        "aarch64",
        "arm64-v8a",
        "armeabi-v7a",
        "universal",
        "x86",
        "x86_64",
    },
    "ios": {"aarch64", "universal"},
}
NATIVE_MOBILE_ARCHITECTURES = {
    "android": {"aarch64", "arm64-v8a", "armeabi-v7a", "x86", "x86_64"},
    "ios": {"aarch64"},
}
CONTAINER_ARCHITECTURES = {"aarch64", "x86_64"}
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SCHEMA_BYTES = 128 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000
MAX_STRING_CHARS = 16_384
MAX_MAPPINGS = 256
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 64 * 1024
MAX_SOURCE_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_SOURCE_REPOSITORIES = 256
MAX_SUBMODULE_DEPTH = 16
MAX_OBJECT_PACK_ENTRIES = 4096
GIT_TIMEOUT_SECONDS = 20
MUTABLE_REVISION_LABELS = {
    "candidate",
    "current",
    "dev",
    "development",
    "edge",
    "head",
    "latest",
    "main",
    "master",
    "nightly",
    "prod",
    "production",
    "stable",
    "trunk",
}
SCHEMA_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "const",
    "enum",
    "format",
    "items",
    "maxItems",
    "maxLength",
    "minimum",
    "minLength",
    "pattern",
    "properties",
    "required",
    "title",
    "type",
}

REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REVISION_BYTES_RE = re.compile(rb"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXECUTABLE_FILTER_KEY_RE = re.compile(
    r"filter\..*\.(clean|process)", re.IGNORECASE
)
PROMISOR_CONFIG_KEY_RE = re.compile(
    r"(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))",
    re.IGNORECASE,
)
SENSITIVE_TEXT_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|SECRET)[A-Z0-9 ]*-----|"
    r"\bBearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\b(?:password|passwd|secret|access[_ -]?token|refresh[_ -]?token|"
    r"private[_ -]?key|authorization)\s*[:=])"
)


class ManifestError(Exception):
    """An input or consistency error safe to display without input contents."""


def fail(message: str) -> NoReturn:
    raise ManifestError(message)


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON object key")
        result[key] = value
    return result


def _reject_non_integer_number(value: str) -> NoReturn:
    del value
    fail("floating-point values are not supported")


def _reject_json_constant(value: str) -> NoReturn:
    del value
    fail("non-standard JSON constants are not supported")


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in value.items()}
    return value


def _bound_tree(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            fail("manifest exceeds the JSON node limit")
        if depth > MAX_JSON_DEPTH:
            fail("manifest exceeds the JSON nesting limit")
        if isinstance(current, str) and len(current) > MAX_STRING_CHARS:
            fail("manifest contains an oversized string")
        if isinstance(current, dict):
            for key, item in current.items():
                if len(key) > MAX_STRING_CHARS:
                    fail("manifest contains an oversized object key")
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def _load_json(path: Path, limit: int, label: str) -> Any:
    try:
        with path.open("rb") as source:
            raw = source.read(limit + 1)
    except OSError:
        fail(f"cannot read {label}")
    if len(raw) > limit:
        fail(f"{label} exceeds the input size limit")
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_float=_reject_non_integer_number,
            parse_constant=_reject_json_constant,
        )
    except ManifestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        fail(f"{label} is not valid bounded UTF-8 JSON")
    try:
        parsed = _normalize(parsed)
    except RecursionError:
        fail(f"{label} exceeds the JSON nesting limit")
    _bound_tree(parsed)
    return parsed


def _resolve_schema_ref(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        fail("schema contains an unsupported reference")
    value: Any = root
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or part not in value:
            fail("schema contains an unresolved reference")
        value = value[part]
    if not isinstance(value, dict):
        fail("schema reference does not point to an object")
    return value


def _check_schema_supported(schema: dict[str, Any]) -> None:
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("release-set schema has an unsupported JSON Schema version")
    stack = [schema]
    while stack:
        node = stack.pop()
        for keyword in node:
            if keyword not in SCHEMA_KEYWORDS:
                fail("release-set schema contains an unsupported validation keyword")
        if "type" in node and (
            not isinstance(node["type"], str)
            or node["type"] not in {"object", "array", "string", "integer", "boolean"}
        ):
            fail("release-set schema contains an unsupported type")
        if node.get("type") == "object" and node.get("additionalProperties") is not False:
            fail("release-set schema must close every object to unknown fields")
        if "additionalProperties" in node and node["additionalProperties"] is not False:
            fail("release-set schema must close every object to unknown fields")
        if "format" in node and node["format"] != "date":
            fail("release-set schema contains an unsupported format")
        if "required" in node and (
            not isinstance(node["required"], list)
            or any(not isinstance(item, str) for item in node["required"])
        ):
            fail("release-set schema contains an invalid required-field list")
        if "enum" in node and not isinstance(node["enum"], list):
            fail("release-set schema contains an invalid enum")
        for bound in ("minimum", "minLength", "maxLength", "minItems", "maxItems"):
            if bound in node and type(node[bound]) is not int:
                fail("release-set schema contains an invalid bound")
        pattern = node.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                fail("release-set schema contains an invalid pattern")
            try:
                re.compile(pattern)
            except (TypeError, re.error):
                fail("release-set schema contains an invalid pattern")
        reference = node.get("$ref")
        if reference is not None and not isinstance(reference, str):
            fail("release-set schema contains an invalid reference")
        if reference is not None:
            _resolve_schema_ref(schema, reference)
        for key in ("properties", "$defs"):
            values = node.get(key, {})
            if not isinstance(values, dict):
                fail("release-set schema contains an invalid schema map")
            for child in values.values():
                if not isinstance(child, dict):
                    fail("release-set schema contains an invalid schema node")
                stack.append(child)
        if "items" in node:
            child = node["items"]
            if not isinstance(child, dict):
                fail("release-set schema contains an invalid array schema")
            stack.append(child)


def _schema_type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return type(value) is int
    if expected == "boolean":
        return type(value) is bool
    return False


def _validate_schema(
    value: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
    path: str = "$",
    depth: int = 0,
) -> None:
    if depth > MAX_JSON_DEPTH:
        fail(f"{path} exceeds the schema nesting limit")
    if "$ref" in schema:
        target = _resolve_schema_ref(root, schema["$ref"])
        _validate_schema(value, target, root, path, depth + 1)
        return

    expected = schema.get("type")
    if expected is not None and not _schema_type_matches(value, expected):
        fail(f"{path} has the wrong JSON type")
    if "const" in schema and value != schema["const"]:
        fail(f"{path} has an unsupported format version")
    if "enum" in schema and value not in schema["enum"]:
        fail(f"{path} has an unsupported value")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get(
            "maxLength", MAX_STRING_CHARS
        ):
            fail(f"{path} has an invalid string length")
        pattern = schema.get("pattern")
        if pattern is not None and re.fullmatch(pattern, value) is None:
            fail(f"{path} has an invalid string format")
        if schema.get("format") == "date":
            try:
                if date.fromisoformat(value).isoformat() != value:
                    fail(f"{path} must use YYYY-MM-DD")
            except ValueError:
                fail(f"{path} must use YYYY-MM-DD")
    elif type(value) is int:
        if "minimum" in schema and value < schema["minimum"]:
            fail(f"{path} is below its minimum")
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 100_000):
            fail(f"{path} has an invalid item count")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                _validate_schema(item, item_schema, root, f"{path}[{index}]", depth + 1)
    elif isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                fail(f"{path}.{key} is required")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key not in properties:
                if schema.get("additionalProperties", True) is False:
                    fail(f"{path} contains an unsupported field")
                continue
            _validate_schema(item, properties[key], root, f"{path}.{key}", depth + 1)


def _walk_strings(value: Any) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if any(ord(character) < 0x20 or ord(character) == 0x7F for character in item):
                fail("manifest contains control characters")
            if SENSITIVE_TEXT_RE.search(item):
                fail("manifest contains credential-like text")
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _validate_reference(reference: str, field: str) -> None:
    if reference.startswith("sha256:"):
        if SHA256_RE.fullmatch(reference[7:]) is None:
            fail(f"{field} has an invalid digest reference")
        return
    if reference.startswith("urn:lomi:"):
        if re.fullmatch(r"urn:lomi:[A-Za-z0-9][A-Za-z0-9._:/-]{0,480}", reference) is None:
            fail(f"{field} has an invalid public reference")
        if any(part in {".", ".."} for part in reference.split("/")):
            fail(f"{field} has an invalid public reference")
        return
    try:
        parsed = urlsplit(reference)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        fail(f"{field} has an invalid public URL")
    if (
        parsed.scheme != "https"
        or not hostname
        or hostname != hostname.lower()
        or not hostname.isascii()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in reference
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        fail(f"{field} must be a credential-free HTTPS, URN, or digest reference")


def _validate_references(value: Any, path: str = "$", depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        fail("manifest exceeds the reference nesting limit")
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if key == "reference" and isinstance(item, str):
                _validate_reference(item, child_path)
            else:
                _validate_references(item, child_path, depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_references(item, f"{path}[{index}]", depth + 1)


def _canonical_bytes(manifest: dict[str, Any]) -> bytes:
    try:
        rendered = json.dumps(
            manifest,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        fail("manifest cannot be canonically encoded")
    return (rendered + "\n").encode("utf-8")


def _parse_mapping(raw: str, known: set[str], label: str) -> tuple[str, Path]:
    name, separator, value = raw.partition("=")
    if not separator or name not in known or not value:
        fail(f"invalid {label} mapping")
    return name, Path(value)


def _collect_mappings(values: list[str], known: set[str], label: str) -> dict[str, Path]:
    if len(values) > MAX_MAPPINGS:
        fail(f"too many {label} mappings")
    output: dict[str, Path] = {}
    for raw in values:
        name, path = _parse_mapping(raw, known, label)
        if name in output:
            fail(f"duplicate {label} mapping")
        output[name] = path
    return output


def _git_environment() -> dict[str, str]:
    env = {"PATH": os.environ.get("PATH", os.defpath)}
    for key in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
        if key in os.environ:
            env[key] = os.environ[key]
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_VALUE_1": os.devnull,
            "GIT_CONFIG_KEY_2": "core.untrackedCache",
            "GIT_CONFIG_VALUE_2": "false",
        }
    )
    return env


def _git_command(repo: Path, args: list[str]) -> list[str]:
    return [
        "git",
        "-C",
        str(repo),
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.untrackedCache=false",
        *args,
    ]


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=GIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        fail("local source Git inspection could not be stopped")


def _run_git_capture(
    repo: Path,
    args: list[str],
    *,
    max_output: int = MAX_GIT_OUTPUT_BYTES,
    allowed_codes: tuple[int, ...] = (0,),
) -> tuple[bytes, int]:
    try:
        process = subprocess.Popen(
            _git_command(repo, args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
        )
    except OSError:
        fail("local source Git inspection failed")
    if process.stdout is None:
        _stop_process(process)
        fail("local source Git inspection failed")

    output = bytearray()
    reader_error: list[bool] = []

    def collect_bounded_output() -> None:
        try:
            while len(output) <= max_output:
                remaining = max_output + 1 - len(output)
                block = process.stdout.read(min(64 * 1024, remaining))
                if not block:
                    break
                output.extend(block)
        except Exception:
            reader_error.append(True)

    reader = threading.Thread(target=collect_bounded_output, daemon=True)
    reader.start()
    reader.join(GIT_TIMEOUT_SECONDS)
    if reader.is_alive():
        _stop_process(process)
        reader.join(GIT_TIMEOUT_SECONDS)
        fail("local source Git inspection timed out")
    if reader_error:
        _stop_process(process)
        fail("local source Git output could not be read")
    if len(output) > max_output:
        _stop_process(process)
        fail("local source Git output exceeds the inventory limit")
    try:
        return_code = process.wait(timeout=GIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _stop_process(process)
        fail("local source Git inspection timed out")
    if return_code not in allowed_codes:
        fail("local source Git inspection failed")
    return bytes(output), return_code


def _run_git(
    repo: Path,
    args: list[str],
    *,
    max_output: int = MAX_GIT_OUTPUT_BYTES,
    budget: list[int] | None = None,
    allowed_codes: tuple[int, ...] = (0,),
) -> tuple[bytes, int]:
    if budget is not None:
        remaining = MAX_SOURCE_INVENTORY_BYTES - budget[0]
        if remaining <= 0:
            fail("local source inventory exceeds the inspection limit")
        max_output = min(max_output, remaining)
    output, return_code = _run_git_capture(
        repo,
        args,
        max_output=max_output,
        allowed_codes=allowed_codes,
    )
    if budget is not None:
        budget[0] += len(output)
    return output, return_code


def _run_git_quiet(repo: Path, args: list[str]) -> int:
    try:
        process = subprocess.run(
            _git_command(repo, args),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("local source Git inspection failed or timed out")
    return process.returncode


def _git_config_key_names(repo: Path, budget: list[int]) -> list[str]:
    output, return_code = _run_git(
        repo,
        [
            "config",
            "--includes",
            "--null",
            "--name-only",
            "--list",
        ],
        max_output=MAX_GIT_OUTPUT_BYTES,
        budget=budget,
    )
    if return_code != 0:
        fail("local source Git configuration cannot be inspected")
    if output and not output.endswith(b"\0"):
        fail("local source Git configuration inventory is malformed")
    try:
        return [key.decode("utf-8", "strict") for key in output.split(b"\0") if key]
    except UnicodeDecodeError:
        fail("local source Git configuration contains an invalid key")


def _reject_executable_filters(repo: Path, budget: list[int]) -> None:
    config_keys = _git_config_key_names(repo, budget)
    if any(EXECUTABLE_FILTER_KEY_RE.fullmatch(key) for key in config_keys):
        fail("local source uses a configured executable Git filter")


def _reject_partial_clone_state(repo: Path, budget: list[int]) -> None:
    config_keys = _git_config_key_names(repo, budget)
    if any(PROMISOR_CONFIG_KEY_RE.fullmatch(key) for key in config_keys):
        fail("local source uses a partial or promisor Git object store")

    output, _ = _run_git(
        repo,
        ["rev-parse", "--git-path", "objects/pack"],
        budget=budget,
    )
    if not output.endswith(b"\n") or b"\n" in output[:-1]:
        fail("local source Git returned an invalid object store path")
    try:
        pack_directory = Path(os.fsdecode(output[:-1]))
        if not pack_directory.is_absolute():
            pack_directory = repo / pack_directory
        pack_directory = pack_directory.resolve(strict=True)
        if not pack_directory.is_dir():
            fail("local source Git returned an invalid object store path")
        entries = 0
        inspected_name_chars = 0
        with os.scandir(pack_directory) as pack_entries:
            for entry in pack_entries:
                entries += 1
                inspected_name_chars += len(entry.name)
                if (
                    entries > MAX_OBJECT_PACK_ENTRIES
                    or inspected_name_chars > MAX_SOURCE_INVENTORY_BYTES
                ):
                    fail("local source object store exceeds the inspection limit")
                if entry.name.endswith(".promisor"):
                    fail("local source uses a partial or promisor Git object store")
    except FileNotFoundError:
        # An empty repository may not have created objects/pack yet.
        return
    except (OSError, RuntimeError):
        fail("local source object store cannot be inspected")


def _read_revision(repo: Path, reference: str, budget: list[int]) -> str:
    try:
        output, _ = _run_git(
            repo,
            ["rev-parse", "--verify", reference],
            budget=budget,
        )
        value = output.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        fail("local source Git returned an invalid object ID")
    if not REVISION_RE.fullmatch(value):
        fail("local source Git returned a non-immutable object ID")
    return value


def _worktree_root(repo: Path, budget: list[int]) -> Path:
    output, _ = _run_git(repo, ["rev-parse", "--show-toplevel"], budget=budget)
    if not output.endswith(b"\n") or b"\n" in output[:-1]:
        fail("local source Git returned an invalid worktree root")
    try:
        root = Path(os.fsdecode(output[:-1])).resolve(strict=True)
    except (OSError, RuntimeError):
        fail("local source Git returned an unresolved worktree root")
    if not root.is_dir():
        fail("local source Git returned a non-directory worktree root")
    return root


def _configured_filters(repo: Path, budget: list[int]) -> None:
    _reject_executable_filters(repo, budget)


def _has_untracked_files(repo: Path, budget: list[int]) -> bool:
    if budget[0] >= MAX_SOURCE_INVENTORY_BYTES:
        fail("local source inventory exceeds the inspection limit")
    command = _git_command(repo, ["ls-files", "--others", "--exclude-standard", "-z"])
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
        )
    except OSError:
        fail("local source Git inspection failed")
    if process.stdout is None:
        _stop_process(process)
        fail("local source Git inspection failed")

    first_byte: list[bytes] = []
    reader_error: list[bool] = []

    def read_first_byte() -> None:
        try:
            first_byte.append(process.stdout.read(1))
        except Exception:
            reader_error.append(True)

    reader = threading.Thread(target=read_first_byte, daemon=True)
    reader.start()
    reader.join(GIT_TIMEOUT_SECONDS)
    if reader.is_alive():
        _stop_process(process)
        reader.join(GIT_TIMEOUT_SECONDS)
        fail("local source Git inspection timed out")
    if reader_error:
        _stop_process(process)
        fail("local source Git output could not be read")
    if first_byte and first_byte[0]:
        budget[0] += 1
        _stop_process(process)
        return True
    try:
        return_code = process.wait(timeout=GIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _stop_process(process)
        fail("local source Git inspection timed out")
    if return_code != 0:
        fail("local source Git inspection failed")
    return False


def _reject_unsupported_index_flags(repo: Path, budget: list[int]) -> None:
    unmerged, _ = _run_git(
        repo,
        ["ls-files", "--unmerged", "-z"],
        max_output=MAX_SOURCE_INVENTORY_BYTES,
        budget=budget,
    )
    if unmerged:
        fail("local source has an unmerged index state")

    output, _ = _run_git(
        repo,
        ["ls-files", "-v", "-z"],
        max_output=MAX_SOURCE_INVENTORY_BYTES,
        budget=budget,
    )
    for record in output.split(b"\0"):
        if not record:
            continue
        if len(record) < 3 or record[1:2] != b" " or record[:1] != b"H":
            fail("local source has an unsupported index state")

    output, _ = _run_git(
        repo,
        ["ls-files", "--stage", "-z"],
        max_output=MAX_SOURCE_INVENTORY_BYTES,
        budget=budget,
    )
    for record in output.split(b"\0"):
        if not record:
            continue
        header, separator, _ = record.partition(b"\t")
        fields = header.split(b" ")
        if not separator or len(fields) != 3:
            fail("local source index inventory is malformed")
        _, object_id, stage = fields
        if (
            stage != b"0"
            or not REVISION_BYTES_RE.fullmatch(object_id)
            or not object_id.strip(b"0")
        ):
            fail("local source has an unsupported index state")

    output, _ = _run_git(
        repo,
        ["ls-files", "-f", "-z"],
        max_output=MAX_SOURCE_INVENTORY_BYTES,
        budget=budget,
    )
    for record in output.split(b"\0"):
        if not record:
            continue
        if len(record) < 3 or record[1:2] != b" " or record[:1] != b"H":
            fail("local source has an unsupported index state")


def _list_submodules(repo: Path, commit: str, budget: list[int]) -> list[tuple[str, str]]:
    output, _ = _run_git(
        repo,
        ["ls-tree", "-r", "-z", "--full-tree", commit],
        max_output=MAX_SOURCE_INVENTORY_BYTES,
        budget=budget,
    )
    if output and not output.endswith(b"\0"):
        fail("local source tree inventory is malformed")
    submodules: list[tuple[str, str]] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        header, separator, path = record.partition(b"\t")
        fields = header.split(b" ")
        if not separator or len(fields) != 3:
            fail("local source tree inventory is malformed")
        mode, object_type, object_id = fields
        if mode != b"160000":
            continue
        if object_type != b"commit" or not REVISION_BYTES_RE.fullmatch(object_id):
            fail("local source contains an invalid submodule entry")
        if (
            not path
            or path.startswith(b"/")
            or b"\\" in path
            or b":" in path
            or any(part in {b"", b".", b".."} for part in path.split(b"/"))
        ):
            fail("local source contains an unsafe submodule path")
        if len(submodules) >= MAX_SOURCE_REPOSITORIES:
            fail("local source exceeds the submodule inventory limit")
        try:
            path_text = path.decode("utf-8", "strict")
            commit_text = object_id.decode("ascii", "strict")
        except UnicodeDecodeError:
            fail("local source contains a noncanonical submodule path")
        submodules.append((path_text, commit_text))
    return submodules


def _list_index_submodules(repo: Path, budget: list[int]) -> list[tuple[str, str]]:
    output, _ = _run_git(
        repo,
        ["ls-files", "--stage", "-z"],
        max_output=MAX_SOURCE_INVENTORY_BYTES,
        budget=budget,
    )
    if output and not output.endswith(b"\0"):
        fail("local source index inventory is malformed")
    submodules: list[tuple[str, str]] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        header, separator, path = record.partition(b"\t")
        fields = header.split(b" ")
        if not separator or len(fields) != 3:
            fail("local source index inventory is malformed")
        mode, object_id, stage = fields
        if mode != b"160000":
            continue
        if stage != b"0" or not REVISION_BYTES_RE.fullmatch(object_id):
            fail("local source has an unsupported submodule index state")
        if (
            not path
            or path.startswith(b"/")
            or b"\\" in path
            or b":" in path
            or any(part in {b"", b".", b".."} for part in path.split(b"/"))
        ):
            fail("local source contains an unsafe submodule path")
        if len(submodules) >= MAX_SOURCE_REPOSITORIES:
            fail("local source exceeds the submodule inventory limit")
        try:
            path_text = path.decode("utf-8", "strict")
            commit_text = object_id.decode("ascii", "strict")
        except UnicodeDecodeError:
            fail("local source contains a noncanonical submodule path")
        submodules.append((path_text, commit_text))
    return submodules


def _submodule_worktree(root: Path, relative: str) -> Path | None:
    candidate = root
    for part in relative.split("/"):
        candidate = candidate / part
        try:
            metadata = candidate.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            return None
    try:
        final = candidate.lstat()
    except OSError:
        return None
    if not stat.S_ISDIR(final.st_mode):
        return None
    try:
        return candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def _collect_source_repositories(
    root: Path,
    root_commit: str,
    budget: list[int],
) -> tuple[list[tuple[Path, str]], bool]:
    pending: list[tuple[Path, tuple[str, ...], int]] = [(root, (root_commit,), 0)]
    repositories: list[tuple[Path, str]] = []
    seen: set[str] = set()
    clean = True

    while pending:
        repo, expected_commits, depth = pending.pop()
        if depth > MAX_SUBMODULE_DEPTH:
            fail("local source exceeds the nested submodule depth limit")
        key = os.path.normcase(str(repo))
        if key in seen:
            fail("local source contains a repeated submodule worktree")
        seen.add(key)
        if len(repositories) >= MAX_SOURCE_REPOSITORIES:
            fail("local source exceeds the repository inventory limit")

        _configured_filters(repo, budget)
        _reject_partial_clone_state(repo, budget)
        top = _worktree_root(repo, budget)
        if os.path.normcase(str(top)) != os.path.normcase(str(repo)):
            fail("local source mapping must name the exact worktree root")
        commit = _read_revision(repo, "HEAD", budget)
        if expected_commits and commit not in expected_commits:
            if depth == 0:
                fail("local source HEAD changed during inspection")
            clean = False
        _read_revision(repo, f"{commit}^{{tree}}", budget)
        repositories.append((repo, commit))

        submodule_commits: dict[str, set[str]] = {}
        for relative, gitlink_commit in (
            _list_submodules(repo, commit, budget)
            + _list_index_submodules(repo, budget)
        ):
            submodule_commits.setdefault(relative, set()).add(gitlink_commit)
        for relative, expected_submodule_commits in submodule_commits.items():
            worktree = _submodule_worktree(repo, relative)
            if worktree is None:
                clean = False
                continue
            git_dir = worktree / ".git"
            if not git_dir.exists() and not git_dir.is_symlink():
                clean = False
                continue
            if git_dir.is_symlink():
                fail("local source contains an unverifiable submodule Git directory")
            pending.append((worktree, tuple(sorted(expected_submodule_commits)), depth + 1))
        if len(pending) + len(repositories) > MAX_SOURCE_REPOSITORIES:
            fail("local source exceeds the repository inventory limit")

    return repositories, clean


def _repo_index_and_worktree_clean(repo: Path, budget: list[int]) -> bool:
    staged = _run_git_quiet(
        repo,
        [
            "diff",
            "--cached",
            "--quiet",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            "HEAD",
            "--",
        ],
    )
    if staged not in (0, 1):
        fail("local source index inspection failed")
    worktree = _run_git_quiet(
        repo,
        [
            "diff",
            "--quiet",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            "--",
        ],
    )
    if worktree not in (0, 1):
        fail("local source worktree inspection failed")
    has_untracked = _has_untracked_files(repo, budget)
    return staged == 0 and worktree == 0 and not has_untracked


def _verify_source(component: str, declared: dict[str, Any], raw_path: Path) -> None:
    try:
        root = raw_path.resolve(strict=True)
    except (OSError, RuntimeError):
        fail(f"source mapping for {component} does not resolve")
    if not root.is_dir():
        fail(f"source mapping for {component} is not a directory")
    budget = [0]
    _configured_filters(root, budget)
    _reject_partial_clone_state(root, budget)
    top = _worktree_root(root, budget)
    if os.path.normcase(str(top)) != os.path.normcase(str(root)):
        fail(f"source mapping for {component} must name the exact worktree root")
    commit = _read_revision(root, "HEAD", budget)
    tree = _read_revision(root, f"{commit}^{{tree}}", budget)
    if commit != declared["git_commit"] or tree != declared["git_tree"]:
        fail(f"source mapping for {component} does not match the manifest")

    # Discover every initialized nested submodule and inspect its configured
    # filter names before any diff can ask Git to inspect a submodule worktree.
    repositories, nested_clean = _collect_source_repositories(root, commit, budget)
    for repo, _ in repositories:
        _reject_unsupported_index_flags(repo, budget)

    clean = nested_clean
    for repo, _ in repositories:
        if not _repo_index_and_worktree_clean(repo, budget):
            clean = False
    for repo, initial_commit in repositories:
        if _read_revision(repo, "HEAD", budget) != initial_commit:
            fail("local source HEAD changed during inspection")
    if clean is not declared["clean"]:
        fail(f"source mapping for {component} has a different clean-state declaration")


def _sha256_file(path: Path) -> tuple[str, int]:
    if not hasattr(os, "O_NOFOLLOW"):
        fail("mapped artifact verification requires no-follow file opens")

    def metadata(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            value.st_dev,
            value.st_ino,
            stat.S_IFMT(value.st_mode),
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    descriptor: int | None = None
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            fail("mapped artifact must not be a symbolic link")
        if not stat.S_ISREG(before.st_mode):
            fail("mapped artifact must be a regular file")
        if before.st_size < 1 or before.st_size > MAX_ARTIFACT_BYTES:
            fail("mapped artifact exceeds the file size limit")

        flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or metadata(opened) != metadata(before):
            fail("mapped artifact changed while it was opened")

        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as source:
            descriptor = None
            size = 0
            for block in iter(lambda: source.read(1024 * 1024), b""):
                size += len(block)
                if size > MAX_ARTIFACT_BYTES:
                    fail("mapped artifact exceeds the file size limit")
                digest.update(block)
            after_fd = os.fstat(source.fileno())
        after_path = path.lstat()
        if (
            not stat.S_ISREG(after_fd.st_mode)
            or not stat.S_ISREG(after_path.st_mode)
            or metadata(after_fd) != metadata(opened)
            or metadata(after_path) != metadata(opened)
            or size != before.st_size
        ):
            fail("mapped artifact changed while it was read")
        return digest.hexdigest(), size
    except ManifestError:
        raise
    except OSError:
        fail("mapped artifact cannot be read")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _declared_artifacts(components: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    count = 0
    for component, value in components.items():
        for artifact in value.get("artifacts", []):
            count += 1
            if count > MAX_MAPPINGS:
                fail("manifest exceeds the artifact inventory limit")
            artifact_id = artifact["id"]
            if artifact_id in result:
                fail("artifact identifiers must be unique across components")
            result[artifact_id] = {"component": component, **artifact}
    return result


def _verify_mappings(
    manifest: dict[str, Any],
    source_mappings: dict[str, Path],
    artifact_mappings: dict[str, Path],
) -> None:
    components = manifest["components"]
    for component, path in source_mappings.items():
        entry = components.get(component)
        if entry is None:
            fail(f"source mapping names missing component {component}")
        _verify_source(component, entry["source"], path)

    artifacts = _declared_artifacts(components)
    for artifact_id, path in artifact_mappings.items():
        declared = artifacts.get(artifact_id)
        if declared is None:
            fail(f"artifact mapping names missing artifact {artifact_id}")
        actual_hash, actual_size = _sha256_file(path)
        if actual_hash != declared["sha256"] or actual_size != declared["size_bytes"]:
            fail(f"artifact mapping for {artifact_id} does not match the manifest")


def _canonicalize_target_aliases(manifest: dict[str, Any]) -> None:
    """Normalize the closed set of target aliases before schema validation."""
    components = manifest.get("components")
    if not isinstance(components, dict):
        return
    for component in components.values():
        if not isinstance(component, dict):
            continue
        artifacts = component.get("artifacts")
        if not isinstance(artifacts, list):
            continue
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            target = artifact.get("target")
            if not isinstance(target, dict):
                continue
            os_name = target.get("os")
            architecture = target.get("architecture")
            if isinstance(os_name, str):
                target["os"] = TARGET_OS_ALIASES.get(os_name, os_name)
            if isinstance(architecture, str):
                target["architecture"] = TARGET_ARCHITECTURE_ALIASES.get(
                    architecture, architecture
                )


def _validate_artifact_targets(manifest: dict[str, Any]) -> None:
    """Reject component/kind/target combinations outside the product matrix."""
    kind_by_component = {
        "api": {"container"},
        "desktop": {"desktop_bundle", "update_metadata"},
        "host": {"binary", "installer_metadata"},
        "identity": {"container"},
        "mobile": {"mobile_package", "native_mobile"},
        "relay": {"container"},
        "web": {"wasm", "web_bundle"},
    }
    for component_name, component in manifest["components"].items():
        for artifact in component.get("artifacts", []):
            kind = artifact["kind"]
            target = artifact["target"]
            os_name = target["os"]
            architecture = target["architecture"]
            abi = target["abi"]
            artifact_id = artifact["id"]

            if kind not in kind_by_component[component_name]:
                fail(f"artifact {artifact_id} has a kind inconsistent with {component_name}")

            if component_name == "host":
                target_key = (os_name, architecture)
                if target_key not in HOST_TARGET_ABIS or abi != HOST_TARGET_ABIS[target_key]:
                    fail(f"Host artifact {artifact_id} is outside the supported Host target matrix")
                if kind == "installer_metadata" and os_name != "linux":
                    fail(f"Host installer metadata {artifact_id} is outside the Linux bootstrap target matrix")
            elif component_name == "desktop":
                if kind == "update_metadata":
                    if (
                        os_name != "web"
                        or architecture != "universal"
                        or abi not in {"json", "detached-signature"}
                    ):
                        fail(f"Desktop update metadata {artifact_id} has an inconsistent target")
                else:
                    target_key = (os_name, architecture)
                    if target_key not in DESKTOP_TARGET_ABIS or abi != DESKTOP_TARGET_ABIS[target_key]:
                        fail(f"Desktop artifact {artifact_id} is outside the supported Desktop target matrix")
            elif component_name == "mobile":
                allowed_architectures = (
                    MOBILE_PACKAGE_ARCHITECTURES.get(os_name)
                    if kind == "mobile_package"
                    else NATIVE_MOBILE_ARCHITECTURES.get(os_name)
                )
                if allowed_architectures is None or architecture not in allowed_architectures:
                    fail(f"mobile artifact {artifact_id} has an inconsistent platform or architecture")
            elif component_name in {"api", "identity", "relay"}:
                if os_name != "linux" or architecture not in CONTAINER_ARCHITECTURES:
                    fail(f"container artifact {artifact_id} has an inconsistent target")
            elif component_name == "web":
                if kind == "web_bundle" and (os_name != "web" or architecture != "universal"):
                    fail(f"Web bundle {artifact_id} has an inconsistent target")
                if kind == "wasm" and (os_name != "web" or architecture != "wasm32"):
                    fail(f"WebAssembly artifact {artifact_id} has an inconsistent target")


def _notarization_required(component_name: str, artifact: dict[str, Any]) -> bool:
    return component_name in {"host", "desktop"} and artifact["target"]["os"] == "macos"


def _signature_required(artifact: dict[str, Any]) -> bool:
    return artifact["kind"] in {
        "binary",
        "desktop_bundle",
        "mobile_package",
        "native_mobile",
    }


def _required_artifact_gaps(manifest: dict[str, Any]) -> list[str]:
    """List required distributable platform targets absent from this draft."""
    components = manifest["components"]
    host_targets = {
        (artifact["target"]["os"], artifact["target"]["architecture"])
        for artifact in components.get("host", {}).get("artifacts", [])
        if artifact["kind"] == "binary"
    }
    desktop_targets = {
        (artifact["target"]["os"], artifact["target"]["architecture"])
        for artifact in components.get("desktop", {}).get("artifacts", [])
        if artifact["kind"] == "desktop_bundle"
    }
    mobile_platforms = {
        artifact["target"]["os"]
        for artifact in components.get("mobile", {}).get("artifacts", [])
        if artifact["kind"] == "mobile_package"
    }
    has_web_bundle = any(
        artifact["kind"] == "web_bundle"
        for artifact in components.get("web", {}).get("artifacts", [])
    )
    has_desktop_json_metadata = any(
        artifact["kind"] == "update_metadata"
        and artifact["target"]["abi"] == "json"
        for artifact in components.get("desktop", {}).get("artifacts", [])
    )

    missing = [
        f"components.host.targets.{os_name}-{architecture}"
        for os_name, architecture in sorted(HOST_TARGET_ABIS)
        if (os_name, architecture) not in host_targets
    ]
    missing.extend(
        f"components.desktop.targets.{os_name}-{architecture}"
        for os_name, architecture in sorted(DESKTOP_TARGET_ABIS)
        if (os_name, architecture) not in desktop_targets
    )
    missing.extend(
        f"components.mobile.targets.{os_name}.mobile_package"
        for os_name in ("android", "ios")
        if os_name not in mobile_platforms
    )
    if not has_web_bundle:
        missing.append("components.web.targets.web-universal.web_bundle")
    if not has_desktop_json_metadata:
        missing.append("components.desktop.targets.web-universal.update_metadata.json")
    return missing


def _preparation_gaps(manifest: dict[str, Any]) -> tuple[list[str], list[str]]:
    components = manifest["components"]
    missing: list[str] = []
    pending: list[str] = []
    for component in COMPONENTS:
        entry = components.get(component)
        if entry is None:
            missing.append(f"components.{component}")
            continue
        if not entry.get("artifacts"):
            missing.append(f"components.{component}.artifacts")
        if not entry["source"]["clean"]:
            pending.append(f"components.{component}.source.clean")
        for artifact in entry.get("artifacts", []):
            signature_state = artifact["signature"]["state"]
            if _signature_required(artifact):
                signature_pending = signature_state != "passed"
            else:
                signature_pending = signature_state not in {"passed", "not_applicable"}
            if signature_pending:
                pending.append(f"artifacts.{artifact['id']}.signature")
            notarization_state = artifact["notarization"]["state"]
            expected_notarization = "passed" if _notarization_required(component, artifact) else "not_applicable"
            if notarization_state != expected_notarization:
                pending.append(f"artifacts.{artifact['id']}.notarization")

    missing.extend(_required_artifact_gaps(manifest))

    for section in RELEASE_SECTIONS:
        if section not in manifest:
            missing.append(section)
    qualification = manifest.get("qualification")
    if qualification is not None:
        if qualification["state"] != "passed":
            pending.append("qualification.state")
        if not qualification["reports"]:
            missing.append("qualification.reports")
        for report in qualification["reports"]:
            if report["state"] != "passed":
                pending.append(f"qualification.reports.{report['id']}")
    return missing, pending


def _validate_release_ready(manifest: dict[str, Any]) -> None:
    components = manifest["components"]
    absent = [component for component in COMPONENTS if component not in components]
    if absent:
        fail("release validation is missing required product components")
    for component in COMPONENTS:
        entry = components[component]
        if not entry.get("artifacts"):
            fail(f"release validation requires artifacts for {component}")
        if entry["source"]["clean"] is not True:
            fail(f"release validation requires a clean declared source for {component}")
        if len(entry["source"]["git_commit"]) != len(entry["source"]["git_tree"]):
            fail(f"release validation found inconsistent Git object formats for {component}")
        for artifact in entry["artifacts"]:
            signature_state = artifact["signature"]["state"]
            if _signature_required(artifact):
                if signature_state != "passed":
                    fail(f"release validation requires a passed signature declaration for {artifact['id']}")
            elif signature_state not in {"passed", "not_applicable"}:
                fail(
                    f"release validation requires a passed or not_applicable signature declaration "
                    f"for {artifact['id']}"
                )
            notarization_state = artifact["notarization"]["state"]
            if _notarization_required(component, artifact):
                if notarization_state != "passed":
                    fail(f"release validation requires passed macOS notarization for {artifact['id']}")
            elif notarization_state != "not_applicable":
                fail(f"release validation requires not_applicable notarization for {artifact['id']}")

    if _required_artifact_gaps(manifest):
        fail("release validation is missing required product platform artifacts")

    missing_sections = [section for section in RELEASE_SECTIONS if section not in manifest]
    if missing_sections:
        fail("release validation is missing required release sections")

    sqlite = manifest["database"]["sqlite"]
    if not sqlite["rollback_min"] <= sqlite["current"] <= sqlite["rollback_max"]:
        fail("SQLite current schema is outside the declared rollback bounds")

    trust = manifest["update_trust"]
    for name in ("public_tuf_root", "policy"):
        record = trust[name]
        revision = record["revision"].lower()
        if (
            revision in MUTABLE_REVISION_LABELS
            or revision.startswith(("refs/heads/", "refs/tags/", "branch-", "tag-"))
            or not SHA256_RE.fullmatch(record["sha256"])
        ):
            fail(f"update trust {name} is not content-pinned to a release revision")

    qualification = manifest["qualification"]
    if qualification["state"] != "passed" or not qualification["reports"]:
        fail("release validation requires completed qualification reports")
    report_ids = [report["id"] for report in qualification["reports"]]
    if len(set(report_ids)) != len(report_ids):
        fail("qualification report identifiers must be unique")
    if any(report["state"] != "passed" for report in qualification["reports"]):
        fail("release validation rejects pending or failed qualification reports")


def _write_canonical(destination: str, canonical: bytes) -> bool:
    if destination == "-":
        sys.stdout.buffer.write(canonical)
        sys.stdout.buffer.flush()
        return True
    output = Path(destination)
    try:
        with output.open("xb") as target:
            target.write(canonical)
            target.flush()
            os.fsync(target.fileno())
    except FileExistsError:
        fail("canonical output already exists")
    except OSError:
        fail("canonical output cannot be created")
    return False


def _load_schema() -> dict[str, Any]:
    schema = _load_json(SCHEMA_PATH, MAX_SCHEMA_BYTES, "release-set schema")
    if not isinstance(schema, dict):
        fail("release-set schema must be a JSON object")
    _check_schema_supported(schema)
    return schema


def _run_validate(args: argparse.Namespace) -> None:
    manifest_path = Path(args.manifest)
    manifest = _load_json(manifest_path, MAX_MANIFEST_BYTES, "release-set manifest")
    if not isinstance(manifest, dict):
        fail("release-set manifest must be a JSON object")
    _canonicalize_target_aliases(manifest)
    schema = _load_schema()
    _validate_schema(manifest, schema, schema)
    _walk_strings(manifest)
    _validate_references(manifest)
    _validate_artifact_targets(manifest)

    source_mappings = _collect_mappings(args.source, set(COMPONENTS), "source")
    artifact_names = set(_declared_artifacts(manifest["components"]))
    artifact_mappings = _collect_mappings(args.artifact, artifact_names, "artifact")
    if args.require_complete_mappings:
        if set(source_mappings) != set(COMPONENTS):
            fail("complete mapping validation requires all seven actual source checkouts")
        if set(artifact_mappings) != artifact_names:
            fail("complete mapping validation requires every declared artifact file")
    _verify_mappings(manifest, source_mappings, artifact_mappings)

    if args.mode == "release":
        _validate_release_ready(manifest)
        status = "RELEASE_MANIFEST_DECLARATIONS_VALID"
        detail = "recorded qualification and signature states were not independently verified"
    else:
        missing, pending = _preparation_gaps(manifest)
        status = "PREPARATION_ONLY"
        detail = (
            f"missing_for_release={','.join(missing) if missing else 'none'} "
            f"pending_for_release={','.join(pending) if pending else 'none'}"
        )

    canonical = _canonical_bytes(manifest)
    digest = hashlib.sha256(canonical).hexdigest()
    wrote_stdout = False
    if args.canonical_out is not None:
        if args.canonical_out != "-":
            try:
                if manifest_path.resolve(strict=True) == Path(args.canonical_out).resolve(strict=False):
                    fail("canonical output must not overwrite the input manifest")
            except (OSError, RuntimeError):
                fail("canonical output path cannot be resolved")
        wrote_stdout = _write_canonical(args.canonical_out, canonical)

    summary = (
        f"{status} sha256={digest} verified_sources={len(source_mappings)} "
        f"verified_artifacts={len(artifact_mappings)}; {detail}"
    )
    print(summary, file=sys.stderr if wrote_stdout else sys.stdout)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate/canonicalize an offline release-set manifest; no publication or qualification is performed."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate", help="validate a release-set manifest")
    validate.add_argument("manifest", help="UTF-8 JSON manifest")
    validate.add_argument(
        "--mode",
        choices=("preparation", "release"),
        default="preparation",
        help="preparation never claims qualification; release checks recorded readiness declarations",
    )
    validate.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="COMPONENT=PATH",
        help="read-only local Git source mapping (repeatable)",
    )
    validate.add_argument(
        "--artifact",
        action="append",
        default=[],
        metavar="ARTIFACT_ID=PATH",
        help="read-only local artifact mapping (repeatable)",
    )
    validate.add_argument(
        "--require-complete-mappings",
        action="store_true",
        help="require all seven source checkouts and every declared artifact file (publication gate)",
    )
    validate.add_argument(
        "--canonical-out",
        metavar="PATH|-",
        help="write compact canonical JSON to a new file, or stdout with '-'",
    )
    validate.set_defaults(handler=_run_validate)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        args.handler(args)
    except ManifestError as error:
        print(f"release-set: {error}", file=sys.stderr)
        return 2
    except (KeyError, TypeError, RecursionError):
        print("release-set: manifest/schema consistency error", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
