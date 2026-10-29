"""Validate the narrow fork→setsid→exec→registered-reparent fixture."""


def validate(value, failure_case=False):
    if value.get("schema") != "reparent-v1" or value.get("cleanupConfirmed") is not True or value.get("numericSignalsUsed") is not False or value.get("execBeforeRegistration") is not True or value.get("middleOwnedWait") is not True:
        return False
    owner = value["self"]
    if owner["outcome"] != "Observed" or owner["bytes"] != 40 or any(type(owner[key]) is not int or owner[key] <= 0 for key in ("pid", "sid", "resource", "jetsam")):
        return False
    for key in ("middle", "leafBefore", "leafSetsid", "leafExec"):
        sample = value[key]
        if sample["outcome"] != "Observed" or sample["bytes"] != 40 or any(type(sample[field]) is not int or sample[field] <= 0 for field in ("pid", "sid", "resource", "jetsam")) or any(sample[field] != owner[field] for field in ("resource", "jetsam")):
            return False
    leaf = value["leafBefore"]["pid"]
    if leaf <= 0 or leaf in (owner["pid"], value["middle"]["pid"]) or value["middle"]["pid"] == owner["pid"]:
        return False
    if any(value[key]["pid"] != leaf or value[key]["sid"] != leaf for key in ("leafSetsid", "leafExec")):
        return False
    expected = {"initial": 1, "together": 3, "final": 1}
    if not failure_case:
        expected["orphan"] = 2
    for key, active in expected.items():
        sample = value["usage"][key]
        if sample["outcome"] != "Observed" or any(type(sample[field]) is not int for field in ("started", "exited", "active")) or sample["exited"] < 0 or sample["started"] - sample["exited"] != active or sample["active"] != active:
            return False
    if failure_case:
        return value.get("scenario") == "registration-failure" and value.get("outcome") == "Unrun" and value.get("registrationAccepted") is False and value.get("orphaned") is False and value.get("leafWaitByMiddle") is True and value.get("leafExitEvent") is False
    sample = value["leafReparented"]
    return value.get("scenario") == "normal" and value.get("outcome") == "Observed" and value.get("registrationAccepted") is True and value.get("orphaned") is True and value.get("leafWaitByMiddle") is False and value.get("leafExitEvent") is True and value.get("auditValidAfterExec") is True and value.get("leafObservedPpid") == 1 and sample["outcome"] == "Observed" and sample["pid"] == leaf and sample["sid"] == leaf and all(sample[key] == owner[key] for key in ("resource", "jetsam"))
