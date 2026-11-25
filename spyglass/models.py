"""Shared result structure for every security check."""
from dataclasses import dataclass, asdict, field

PASS = "PASS"
FAIL = "FAIL"
WARNING = "WARNING"
NOT_ASSESSED = "NOT ASSESSED"

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"


@dataclass
class Finding:
    check_id: str          # e.g. "S3-001"
    title: str             # what was checked
    service: str           # S3, IAM, EC2, CloudTrail
    resource: str          # affected resource identifier
    status: str            # PASS / FAIL / WARNING / NOT ASSESSED
    severity: str          # severity if it fails (still recorded for PASS)
    description: str       # why this matters
    remediation: str       # how to fix
    evidence: str = ""     # what AWS actually returned

    def to_dict(self) -> dict:
        return asdict(self)


def not_assessed(check_id, title, service, resource, severity, description, remediation, reason):
    """Helper for checks that could not run (e.g. AccessDenied)."""
    return Finding(check_id, title, service, resource, NOT_ASSESSED, severity,
                   description, remediation, evidence=f"Could not assess: {reason}")
