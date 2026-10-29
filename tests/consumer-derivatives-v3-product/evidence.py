"""Pure exact-byte capture, admission, pin-fill, and stage-evidence checks."""
from pathlib import Path
import hashlib
import json
import re


class Rejected(ValueError):
    pass


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw, label="JSON"):
    if type(raw) is not bytes:
        raise Rejected(label + " must be bytes")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise Rejected("invalid " + label) from error


def parse_json_lines(raw, *, max_bytes=64 * 1024 * 1024):
    if type(raw) is not bytes or len(raw) > max_bytes:
        raise Rejected("catalog capture missing or over evidence bound")
    rows = []
    for line in raw.splitlines():
        if not line:
            continue
        row = strict_json(line, "catalog capture row")
        if type(row) is not dict or type(row.get("kind")) is not str:
            raise Rejected("invalid catalog capture row")
        rows.append(row)
    if not rows:
        raise Rejected("empty catalog capture")
    return rows


def verify_capture(raw, *, expected_kinds=None):
    rows = parse_json_lines(raw)
    seen = set()
    counts = {}
    functions = {}
    for row in rows:
        kind = row["kind"]
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "function":
            signature = row.get("signature")
            if type(signature) is not str or signature in functions:
                raise Rejected("function capture duplicate or missing signature")
            definition = row.get("definition")
            encoded = row.get("definitionUtf8Hex")
            digest = row.get("catalogSha256")
            acl = row.get("acl")
            if (type(definition) is not str or type(encoded) is not str
                    or re.fullmatch(r"(?:[0-9a-f]{2})*", encoded) is None
                    or type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                    or type(acl) is not list):
                raise Rejected("function capture fields are malformed")
            definition_bytes = definition.encode("utf-8", "strict")
            if definition_bytes.hex() != encoded or sha256(definition_bytes) != digest:
                raise Rejected("function definition raw UTF-8 bytes or digest mismatch")
            if row.get("owner") is None or type(row.get("securityDefiner")) is not bool:
                raise Rejected("function owner or security mode missing")
            functions[signature] = row
        else:
            identity = row.get("name", row.get("relation", row.get("signature", "")))
            marker = (kind, identity, json.dumps(row, sort_keys=True, ensure_ascii=False))
            if marker in seen:
                raise Rejected("duplicate catalog capture row")
            seen.add(marker)
    if expected_kinds is not None and set(counts) != set(expected_kinds):
        raise Rejected("catalog category closure mismatch")
    return {"rows": rows, "functions": functions, "counts": counts}


def exact_capture_equality(left, right):
    """Compare parsed rows without rewriting SQL definitions or ACL rows."""
    a = verify_capture(left)
    b = verify_capture(right)
    return a["rows"] == b["rows"]


def stable_catalog_equality(left, right):
    """Compare raw catalog rows while mapping only internal FK trigger names.

    Raw captures and function-definition bytes remain untouched. PostgreSQL
    allocates database-local OIDs into internal RI_ConstraintTrigger names;
    those rows are compared by their stable relation/constraint/function and
    trigger-structure fields instead.
    """
    a = verify_capture(left)["rows"]
    b = verify_capture(right)["rows"]

    def row_key(row):
        return json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    def split(rows):
        stable = []
        internal = []
        for row in rows:
            if row.get("kind") == "trigger" and row.get("internal") is True:
                name = row.get("name")
                if type(name) is not str or not re.fullmatch(r"RI_ConstraintTrigger_[a-z]_[0-9]+", name):
                    raise Rejected("internal trigger name is outside PostgreSQL FK identity shape")
                required = (
                    "relation", "constraint", "enabled", "internal", "function", "type",
                    "deferrable", "deferred", "referencedRelation", "constraintIndex", "columns",
                )
                if any(key not in row for key in required):
                    raise Rejected("internal FK trigger structure is incomplete")
                internal.append(tuple(row[key] for key in required))
            else:
                stable.append(row_key(row))
        return sorted(stable), sorted(internal, key=lambda item: json.dumps(item, sort_keys=True))

    return split(a) == split(b)


def raw_function_map(capture, signatures):
    facts = verify_capture(capture)
    if set(facts["functions"]) != set(signatures):
        raise Rejected("function reference signature closure mismatch")
    return {signature: facts["functions"][signature] for signature in sorted(signatures)}


def validate_null_pins(contract, helper_contract):
    if contract.get("status") != "UNMEASURED_CATALOG_FAIL_CLOSED":
        raise Rejected("catalog contract no longer fails closed")
    if helper_contract.get("status") != "UNMEASURED_CATALOG_FAIL_CLOSED":
        raise Rejected("helper contract no longer fails closed")
    fields = ("old_catalog_sha256", "new_catalog_sha256", "old_acl", "new_acl")
    roots = contract.get("roots")
    prerequisites = contract.get("prerequisites")
    helpers = helper_contract.get("helpers")
    if type(roots) is not list or type(prerequisites) is not list or type(helpers) is not list:
        raise Rejected("pin contracts have no required rows")
    if any(row.get(field) is not None for row in roots + helpers for field in fields):
        raise Rejected("original root/helper pin source was modified")
    if any(row.get("catalog_sha256") is not None or row.get("acl") is not None
           for row in prerequisites):
        raise Rejected("original prerequisite pin source was modified")


def null_value_spans(text):
    """Return JSON null spans with duplicate-key and full-input rejection."""
    decoder = json.JSONDecoder()
    spans = {}

    def whitespace(index):
        while index < len(text) and text[index].isspace():
            index += 1
        return index

    def parse(index, path):
        index = whitespace(index)
        if index >= len(text):
            raise Rejected("truncated pin JSON")
        if text[index] == "{":
            index = whitespace(index + 1)
            seen = set()
            if index < len(text) and text[index] == "}":
                return index + 1
            while True:
                key, end = decoder.raw_decode(text, index)
                if type(key) is not str or key in seen:
                    raise Rejected("duplicate or non-string pin JSON key")
                seen.add(key)
                index = whitespace(end)
                if index >= len(text) or text[index] != ":":
                    raise Rejected("pin JSON colon")
                index = whitespace(parse(index + 1, (*path, key)))
                if index < len(text) and text[index] == "}":
                    return index + 1
                if index >= len(text) or text[index] != ",":
                    raise Rejected("pin JSON object delimiter")
                index = whitespace(index + 1)
        elif text[index] == "[":
            index = whitespace(index + 1)
            ordinal = 0
            if index < len(text) and text[index] == "]":
                return index + 1
            while True:
                index = whitespace(parse(index, (*path, ordinal)))
                ordinal += 1
                if index < len(text) and text[index] == "]":
                    return index + 1
                if index >= len(text) or text[index] != ",":
                    raise Rejected("pin JSON array delimiter")
                index = whitespace(index + 1)
        else:
            value, end = decoder.raw_decode(text, index)
            if value is None:
                spans[path] = (index, end)
            return end

    end = parse(0, ())
    if whitespace(end) != len(text):
        raise Rejected("trailing pin JSON bytes")
    return spans


def fill_null_spans(raw, values, correlations):
    """Replace only the exact reviewed NULL tokens; preserve all other bytes."""
    if type(raw) is not bytes or type(values) is not dict or set(values) != set(correlations):
        raise Rejected("pin fill input shape")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise Rejected("pin source must be UTF-8") from error
    spans = null_value_spans(text)
    if set(spans) != set(values):
        raise Rejected("NULL token closure differs from explicit pin allowlist")
    edits = []
    for path, (start, end) in spans.items():
        value = values[path]
        if value is None:
            raise Rejected("NULL pin value cannot authorize an operator")
        start_byte = len(text[:start].encode("utf-8"))
        end_byte = len(text[:end].encode("utf-8"))
        replacement = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        edits.append((start_byte, end_byte, replacement, path))
    output = bytearray()
    previous = 0
    deltas = []
    for start, end, replacement, path in sorted(edits):
        output.extend(raw[previous:start])
        derived_start = len(output)
        output.extend(replacement)
        deltas.append({
            "path": list(path),
            "sourceStart": start,
            "sourceEnd": end,
            "derivedStart": derived_start,
            "derivedEnd": len(output),
            "sourceHex": raw[start:end].hex(),
            "derivedHex": replacement.hex(),
            "correlation": correlations[path],
        })
        previous = end
    output.extend(raw[previous:])
    return bytes(output), deltas


def fill_operator_embedded_contract(raw_operator, marker, contract_json, group, values, correlations):
    """Fill one uniquely embedded source contract block and no SQL elsewhere."""
    if type(raw_operator) is not bytes or type(contract_json) is not bytes:
        raise Rejected("operator pin fill requires raw bytes")
    tag = marker.encode("ascii")
    if raw_operator.count(tag) != 2:
        raise Rejected("operator JSON delimiter count")
    start = raw_operator.index(tag) + len(tag)
    end = raw_operator.index(tag, start)
    embedded = raw_operator[start:end]
    if strict_json(embedded, "operator embedded contract") != strict_json(contract_json, "pending contract"):
        raise Rejected("operator embedded contract differs from admitted source")
    json_values = {}
    json_correlations = {}
    for path, value in values.items():
        if len(path) == 3 and path[0] == group:
            json_values[(path[1], path[2])] = value
            json_correlations[(path[1], path[2])] = correlations[path]
    filled, deltas = fill_null_spans(embedded, json_values, json_correlations)
    output = raw_operator[:start] + filled + raw_operator[end:]
    for delta in deltas:
        delta["operatorBlock"] = marker
        delta["sourceStart"] += start
        delta["sourceEnd"] += start
        delta["derivedStart"] += start
        delta["derivedEnd"] += start
    return output, deltas


def pin_values_from_references(contract, old_capture, new_capture, helper_contract, old_helper_capture, new_helper_capture):
    """Derive pin values only from independently captured reference databases."""
    validate_null_pins(contract, helper_contract)
    old = verify_capture(old_capture)["functions"]
    new = verify_capture(new_capture)["functions"]
    old_helpers = verify_capture(old_helper_capture)["functions"]
    new_helpers = verify_capture(new_helper_capture)["functions"]
    values = {"catalog-contract.pending.json": {}, "helper-seal.pending.json": {}}
    correlations = {"catalog-contract.pending.json": {}, "helper-seal.pending.json": {}}
    for group, rows in (("roots", contract["roots"]), ("prerequisites", contract["prerequisites"])):
        for index, row in enumerate(rows):
            signature = row.get("signature")
            if type(signature) is not str:
                raise Rejected("contract signature missing")
            states = ("old", "new") if group == "roots" else ("new",)
            for state in states:
                ref_map = old if state == "old" else new
                if signature not in ref_map:
                    raise Rejected("reference function missing: " + signature)
                ref = ref_map[signature]
                owner_key = "old_owner" if group == "helpers" else "owner"
                if group == "roots" and ref["owner"] != row[owner_key]:
                    raise Rejected("reference root owner does not match contract")
                if group == "prerequisites" and ref["owner"] != row[owner_key]:
                    raise Rejected("reference prerequisite owner does not match contract")
                for field, capture_field in (("catalog_sha256", "catalogSha256"), ("acl", "acl")):
                    # Root contracts use old_catalog_sha256/new_catalog_sha256
                    # and old_acl/new_acl. Prerequisites have one pinned new
                    # state and retain catalog_sha256/acl. Keep these literal
                    # keys aligned with the frozen contract bytes.
                    key = state + "_" + field if group == "roots" else field
                    pin_path = (group, index, key)
                    if row.get(key) is not None:
                        raise Rejected("original pin is not NULL")
                    value = ref[capture_field]
                    values["catalog-contract.pending.json"][pin_path] = value
                    correlations["catalog-contract.pending.json"][pin_path] = {
                        "referenceState": state,
                        "signature": signature,
                        "captureDefinitionSha256": ref["catalogSha256"],
                        "owner": ref["owner"],
                        "captureAcl": ref["acl"],
                    }
    for index, row in enumerate(helper_contract["helpers"]):
        signature = row.get("signature")
        if type(signature) is not str:
            raise Rejected("helper signature missing")
        for state, ref_map in (("old", old_helpers), ("new", new_helpers)):
            if signature not in ref_map:
                raise Rejected("helper reference function missing")
            ref = ref_map[signature]
            expected_owner = row["old_owner"] if state == "old" else row["new_owner"]
            if ref["owner"] != expected_owner:
                raise Rejected("helper reference owner does not match contract")
            for field in ("catalog_sha256", "acl"):
                pin_path = ("helpers", index, state + "_" + field)
                if row.get(state + "_" + field) is not None:
                    raise Rejected("original helper pin is not NULL")
                value = ref["catalogSha256"] if field == "catalog_sha256" else ref["acl"]
                values["helper-seal.pending.json"][pin_path] = value
                correlations["helper-seal.pending.json"][pin_path] = {
                    "referenceState": state,
                    "signature": signature,
                    "captureDefinitionSha256": ref["catalogSha256"],
                    "owner": ref["owner"],
                    "captureAcl": ref["acl"],
                }
    return values, correlations


S6_ACCEPTANCE_KEYS = {
    "freshLegacyWebAndMobileIssuance",
    "consentFaultRollbackAndSameIdRetry",
    "concurrentOneUseAndLostAckNoReissue",
    "apiPostCommitLostAckUnknown",
    "privateCredentialHashAndTwoAccountInventory",
    "mobileRefreshReplayAndPolicy",
    "mobileDerivativeSelfRevokeAndOwnership",
    "mobilePublicWindowGatesHonored",
    "typedConsumerOverloadAclBoundary",
    "actualRoleIdentitiesChecked",
    "listenersStopped",
    "fixturesRemoved",
    "cleanupCountsVerified",
    "pairingChannelTicketActualTransactions",
    "allFifteenTypedOverloadsExecuted",
    "hostEnrollmentRuntimePublication",
    "transactionLostAckOutcomesVerified",
    "positiveFixtureCleanupVerified",
}


def parse_s6_acceptance(stdout):
    if type(stdout) is not bytes or len(stdout) > 1024 * 1024:
        raise Rejected("S6 stdout outside evidence bound")
    text = stdout.decode("utf-8", "strict")
    if "LOMI_CONSUMER_DERIVATIVE_PRODUCT_FAILURE=" in text:
        raise Rejected("actual-handler test emitted failure marker")
    marker = "LOMI_CONSUMER_DERIVATIVE_PRODUCT_ACCEPTED="
    lines = [line[len(marker):] for line in text.splitlines() if line.startswith(marker)]
    if len(lines) != 1:
        raise Rejected("actual-handler acceptance marker missing or ambiguous")
    result = strict_json(lines[0].encode("utf-8"), "S6 acceptance marker")
    if type(result) is not dict or set(result) != S6_ACCEPTANCE_KEYS:
        raise Rejected("actual-handler acceptance key set drift")
    if any(value is not True for value in result.values()):
        raise Rejected("actual-handler test did not accept every asserted behavior")
    return result


def validate_stage_statuses(statuses, evidence):
    expected = {f"S{index}" for index in range(8)}
    if type(statuses) is not dict or set(statuses) != expected:
        raise Rejected("report must contain S0-S7")
    if type(evidence) is not dict:
        raise Rejected("stage evidence object required")
    for stage, status in statuses.items():
        if status == "PASS" and evidence.get(stage) is not True:
            raise Rejected("stage cannot pass without authoritative evidence")
        if status not in ("PASS", "FAILED", "NOT_RUN"):
            raise Rejected("invalid stage status")

