"""Unit tests for scoring using fabricated findings (NOT real AWS data)."""
from spyglass.models import Finding, PASS, FAIL, WARNING, NOT_ASSESSED
from spyglass.scoring import calculate_score


def f(status, sev):
    return Finding("T-1", "t", "TEST", "r", status, sev, "d", "r", "e")


base = [f(PASS, "HIGH"), f(FAIL, "CRITICAL"), f(WARNING, "LOW")]
a = calculate_score(base)
print("base score:", a["score"], "(expect 100*(1-10.5/18) = 41.7)")

b = calculate_score(base + [f(NOT_ASSESSED, "CRITICAL")] * 3)
print("with 3 unassessed:", b["score"], "coverage", b["coverage_pct"], "complete", b["complete"])
assert b["score"] == a["score"] and not b["complete"]

c = calculate_score([f(NOT_ASSESSED, "HIGH")])
print("all unassessed:", c["score"], c["rating"])
assert c["score"] is None

d = calculate_score([f(PASS, "HIGH")])
print("all pass:", d["score"], d["rating"])
assert d["score"] == 100.0
print("all tests passed")
