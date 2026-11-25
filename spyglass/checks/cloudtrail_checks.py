"""CloudTrail security checks. All calls are read-only."""
from botocore.exceptions import BotoCoreError, ClientError

from spyglass.aws_client import get_client
from spyglass.models import Finding, PASS, FAIL, HIGH, MEDIUM, not_assessed


def _reason(e):
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "Unknown")
    return type(e).__name__


def run_cloudtrail_checks():
    ct = get_client("cloudtrail")

    c1 = ("CT-001", "CloudTrail is configured", HIGH,
          "Without CloudTrail there is no record of who did what in the account, "
          "so incidents cannot be investigated.",
          "Create a multi-region trail that delivers logs to a protected S3 bucket.")
    c2 = ("CT-002", "CloudTrail trail is logging", HIGH,
          "A trail that exists but is stopped records no events.",
          "Start logging on the trail.")
    c3 = ("CT-003", "Log file validation is enabled", MEDIUM,
          "Without validation you cannot prove log files were not altered after delivery.",
          "Enable log file integrity validation on the trail.")

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    except (ClientError, BotoCoreError) as e:
        cid, title, sev, desc, rem = c1
        return [not_assessed(cid, title, "CloudTrail", "(account)", sev, desc, rem, _reason(e))]

    findings = []
    cid, title, sev, desc, rem = c1
    if not trails:
        return [Finding(cid, title, "CloudTrail", "(account)", FAIL, sev, desc, rem,
                        "No CloudTrail trails found in this region.")]
    findings.append(Finding(cid, title, "CloudTrail", "(account)", PASS, sev, desc, rem,
                            f"{len(trails)} trail(s) found: " + ", ".join(t["Name"] for t in trails)))

    for t in trails:
        name = t["Name"]
        ident = t.get("TrailARN") or name

        # CT-002: is it logging?
        cid, title, sev, desc, rem = c2
        try:
            status = ct.get_trail_status(Name=ident)
            if status.get("IsLogging"):
                findings.append(Finding(cid, title, "CloudTrail", name, PASS, sev, desc, rem,
                                        "IsLogging: true"))
            else:
                findings.append(Finding(cid, title, "CloudTrail", name, FAIL, sev, desc, rem,
                                        "IsLogging: false (trail exists but is not recording)."))
        except (ClientError, BotoCoreError) as e:
            findings.append(not_assessed(cid, title, "CloudTrail", name, sev, desc, rem, _reason(e)))

        # CT-003: log file validation (already in describe_trails output)
        cid, title, sev, desc, rem = c3
        if t.get("LogFileValidationEnabled"):
            findings.append(Finding(cid, title, "CloudTrail", name, PASS, sev, desc, rem,
                                    "LogFileValidationEnabled: true"))
        else:
            findings.append(Finding(cid, title, "CloudTrail", name, FAIL, sev, desc, rem,
                                    "LogFileValidationEnabled: false"))
    return findings


if __name__ == "__main__":
    for f in run_cloudtrail_checks():
        print(f"{f.status:13} {f.severity:8} {f.check_id}  {f.resource:26} {f.evidence}")
