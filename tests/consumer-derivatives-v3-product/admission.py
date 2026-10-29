"""Pure validators for the separate two-document root/reviewer admission."""
import hashlib
import json
import re
import uuid

SCOPE = "consumer-derivatives-v3-full-product-s0-s7"


class Rejected(ValueError):
    pass


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw, label):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("ascii"), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as error:
        raise Rejected("invalid " + label) from error


def digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def valid_uuid(value):
    if type(value) is not str:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def validate_receipts(root_raw, independent_raw, *, controller_sha256, manifest_sha256):
    root = strict_json(root_raw, "root run admission")
    review = strict_json(independent_raw, "independent review admission")
    review_keys = {
        "schemaVersion", "scope", "reviewerId", "reviewStatus", "reviewNonce",
        "controllerSha256", "bundleManifestSha256", "reviewedFullS0S7Source",
        "reviewedNoRunBeforeAdmission", "identifiedStageGapsExplicitly",
    }
    if (type(review) is not dict or set(review) != review_keys
            or type(review.get("schemaVersion")) is not int or review["schemaVersion"] != 1
            or review.get("scope") != SCOPE
            or type(review.get("reviewerId")) is not str or not review["reviewerId"].strip()
            or review.get("reviewStatus") != "PASS"
            or not valid_uuid(review.get("reviewNonce"))
            or review.get("controllerSha256") != controller_sha256
            or review.get("bundleManifestSha256") != manifest_sha256
            or review.get("reviewedFullS0S7Source") is not True
            or review.get("reviewedNoRunBeforeAdmission") is not True
            or review.get("identifiedStageGapsExplicitly") is not True):
        raise Rejected("independent review receipt does not admit exact S0-S7 source")
    root_keys = {
        "schemaVersion", "scope", "integratorId", "rootReviewStatus",
        "rootReviewComplete", "executionAuthorized",
        "admissionNonce", "controllerSha256", "bundleManifestSha256",
        "independentReviewSha256", "postgresVersion", "databaseName",
        "maximumConnections", "maximumRealRolePools", "maximumPoolSize",
        "originalDeadlineSeconds", "productionTargetOption",
        "acknowledgedStageGaps",
    }
    if (type(root) is not dict or set(root) != root_keys
            or type(root.get("schemaVersion")) is not int or root["schemaVersion"] != 1
            or root.get("scope") != SCOPE
            or type(root.get("integratorId")) is not str or not root["integratorId"].strip()
            or root.get("integratorId") == review.get("reviewerId")
            or root.get("rootReviewStatus") != "PASS"
            or root.get("rootReviewComplete") is not True
            or root.get("executionAuthorized") is not True
            or not valid_uuid(root.get("admissionNonce"))
            or root.get("controllerSha256") != controller_sha256
            or root.get("bundleManifestSha256") != manifest_sha256
            or root.get("independentReviewSha256") != sha256(independent_raw)
            or root.get("postgresVersion") != "18.6"
            or root.get("databaseName") != "lomi_auth_test"
            or type(root.get("maximumConnections")) is not int or root["maximumConnections"] != 16
            or type(root.get("maximumRealRolePools")) is not int or root["maximumRealRolePools"] != 4
            or type(root.get("maximumPoolSize")) is not int or root["maximumPoolSize"] != 2
            or type(root.get("originalDeadlineSeconds")) is not int or root["originalDeadlineSeconds"] != 900
            or root.get("productionTargetOption") is not False
            or root.get("acknowledgedStageGaps") is not True):
        raise Rejected("root receipt does not admit exact bounded private fixture")
    return {"root": root, "independentReview": review,
            "independentReviewSha256": sha256(independent_raw)}

