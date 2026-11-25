"""Runs every check module and returns one flat list of Finding objects."""
from spyglass.checks.cloudtrail_checks import run_cloudtrail_checks
from spyglass.checks.ec2_checks import run_ec2_checks
from spyglass.checks.iam_checks import run_iam_checks
from spyglass.checks.s3_checks import run_s3_checks
from spyglass.models import HIGH, not_assessed

MODULES = [
    ("S3", "S3-000", run_s3_checks),
    ("IAM", "IAM-000", run_iam_checks),
    ("EC2", "EC2-000", run_ec2_checks),
    ("CloudTrail", "CT-000", run_cloudtrail_checks),
]


def run_all_checks():
    """Return all findings. A crashing module becomes a NOT ASSESSED finding."""
    findings = []
    for service, cid, fn in MODULES:
        try:
            findings.extend(fn())
        except Exception as e:  # deliberate catch-all: never let one module abort the scan
            findings.append(not_assessed(
                cid, f"{service} checks could run", service, "(module)", HIGH,
                f"The {service} check module failed unexpectedly, so no {service} result is available.",
                "Check application logs and permissions, then rerun the scan.",
                type(e).__name__))
    return findings


if __name__ == "__main__":
    from collections import Counter
    results = run_all_checks()
    print("total findings:", len(results))
    for status, n in sorted(Counter(f.status for f in results).items()):
        print(f"  {status:13} {n}")
