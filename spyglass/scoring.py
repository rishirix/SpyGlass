"""Risk scoring: converts Finding objects into a 0-100 security score.

score = 100 * (1 - penalty / max_points) over ASSESSED checks only.
FAIL = full severity weight, WARNING = half, PASS = 0.
NOT ASSESSED is excluded from the score and reported as a coverage gap;
it is never treated as a pass.
"""
from collections import Counter

import config
from spyglass.models import FAIL, NOT_ASSESSED, PASS, WARNING

WARNING_FACTOR = 0.5


def _rating(score):
    if score is None:
        return "UNRATED"
    if score >= 80:
        return "GOOD"
    if score >= 60:
        return "FAIR"
    if score >= 40:
        return "POOR"
    return "CRITICAL"


def calculate_score(findings) -> dict:
    weights = config.SEVERITY_WEIGHTS
    max_points = 0.0
    penalty = 0.0
    by_status = Counter()
    fail_by_severity = Counter()

    for f in findings:
        by_status[f.status] += 1
        if f.status == NOT_ASSESSED:
            continue
        w = weights.get(f.severity, 0)
        max_points += w
        if f.status == FAIL:
            penalty += w
            fail_by_severity[f.severity] += 1
        elif f.status == WARNING:
            penalty += w * WARNING_FACTOR

    total = len(findings)
    not_assessed = by_status[NOT_ASSESSED]
    assessed = total - not_assessed
    coverage = round(100 * assessed / total, 1) if total else 0.0

    score = round(100 * (1 - penalty / max_points), 1) if max_points > 0 else None

    return {
        "score": score,
        "rating": _rating(score),
        "complete": not_assessed == 0 and total > 0,
        "coverage_pct": coverage,
        "total_checks": total,
        "passed": by_status[PASS],
        "failed": by_status[FAIL],
        "warnings": by_status[WARNING],
        "not_assessed": not_assessed,
        "critical_findings": fail_by_severity["CRITICAL"],
        "high_findings": fail_by_severity["HIGH"],
        "max_points": max_points,
        "penalty_points": penalty,
        "method": ("Score = 100 x (1 - penalty/max). Weights: Critical 10, High 7, "
                   "Medium 4, Low 1. FAIL counts full weight, WARNING half, PASS zero. "
                   "NOT ASSESSED checks are excluded and lower the coverage figure; "
                   "they are never counted as passes."),
    }


if __name__ == "__main__":
    import json
    from spyglass.checks import run_all_checks
    print(json.dumps(calculate_score(run_all_checks()), indent=2))
