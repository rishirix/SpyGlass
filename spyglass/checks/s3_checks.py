"""S3 security checks. All calls are read-only."""
from botocore.exceptions import BotoCoreError, ClientError

from spyglass.aws_client import get_client
from spyglass.models import (Finding, PASS, FAIL, WARNING, HIGH, MEDIUM, LOW, CRITICAL,
                             not_assessed)

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
DENIED = {"AccessDenied", "AccessDeniedException", "AllAccessDisabled"}


def _code(e):
    return e.response.get("Error", {}).get("Code", "Unknown")


def _na(cid, title, bucket, sev, desc, rem, e):
    reason = _code(e) if isinstance(e, ClientError) else type(e).__name__
    return not_assessed(cid, title, "S3", bucket, sev, desc, rem, reason)


# ---- S3-001: public access (ACL + policy) --------------------------------
def check_public_access(s3, bucket):
    cid, title, sev = "S3-001", "Bucket is not publicly accessible", CRITICAL
    desc = ("Publicly readable buckets are a leading cause of data breaches; "
            "anyone on the internet could read or list the contents.")
    rem = ("Remove public ACL grants and public bucket policies, then enable all four "
           "S3 Block Public Access settings.")
    reasons = []
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        for g in acl.get("Grants", []):
            uri = g.get("Grantee", {}).get("URI")
            if uri in (ALL_USERS, AUTH_USERS):
                who = "everyone" if uri == ALL_USERS else "any AWS account"
                reasons.append(f"ACL grants {g.get('Permission')} to {who}")
    except (ClientError, BotoCoreError) as e:
        return _na(cid, title, bucket, sev, desc, rem, e)

    try:
        status = s3.get_bucket_policy_status(Bucket=bucket)
        if status.get("PolicyStatus", {}).get("IsPublic"):
            reasons.append("bucket policy makes the bucket public")
    except ClientError as e:
        if _code(e) != "NoSuchBucketPolicy":
            return _na(cid, title, bucket, sev, desc, rem, e)
    except BotoCoreError as e:
        return _na(cid, title, bucket, sev, desc, rem, e)

    if reasons:
        return Finding(cid, title, "S3", bucket, FAIL, sev, desc, rem, "; ".join(reasons))
    return Finding(cid, title, "S3", bucket, PASS, sev, desc, rem,
                   "No public ACL grants or public policy found.")


# ---- S3-002: block public access -----------------------------------------
def check_block_public_access(s3, bucket):
    cid, title, sev = "S3-002", "Block Public Access is fully enabled", HIGH
    desc = ("Block Public Access is a safety net that prevents accidental public "
            "exposure even if an ACL or policy is later misconfigured.")
    rem = "Enable all four Block Public Access settings on the bucket (and account-wide)."
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if _code(e) == "NoSuchPublicAccessBlockConfiguration":
            return Finding(cid, title, "S3", bucket, FAIL, sev, desc, rem,
                           "No Block Public Access configuration exists on this bucket.")
        return _na(cid, title, bucket, sev, desc, rem, e)
    except BotoCoreError as e:
        return _na(cid, title, bucket, sev, desc, rem, e)

    keys = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
    off = [k for k in keys if not cfg.get(k)]
    if off:
        return Finding(cid, title, "S3", bucket, FAIL, sev, desc, rem,
                       "Disabled settings: " + ", ".join(off))
    return Finding(cid, title, "S3", bucket, PASS, sev, desc, rem, "All four settings enabled.")


# ---- S3-003: default encryption ------------------------------------------
def check_encryption(s3, bucket):
    cid, title, sev = "S3-003", "Default server-side encryption is enabled", MEDIUM
    desc = "Without default encryption, objects may be stored unencrypted at rest."
    rem = "Enable default encryption (SSE-S3 or SSE-KMS) on the bucket."
    try:
        cfg = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]
        algos = [r["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] for r in cfg.get("Rules", [])]
        return Finding(cid, title, "S3", bucket, PASS, sev, desc, rem,
                       "Default encryption: " + ", ".join(algos))
    except ClientError as e:
        if _code(e) == "ServerSideEncryptionConfigurationNotFoundError":
            return Finding(cid, title, "S3", bucket, FAIL, sev, desc, rem,
                           "No default encryption configuration found.")
        return _na(cid, title, bucket, sev, desc, rem, e)
    except BotoCoreError as e:
        return _na(cid, title, bucket, sev, desc, rem, e)


# ---- S3-004: versioning --------------------------------------------------
def check_versioning(s3, bucket):
    cid, title, sev = "S3-004", "Versioning is enabled", LOW
    desc = ("Versioning protects against accidental deletion, overwrites and "
            "ransomware-style tampering by keeping previous object versions.")
    rem = "Enable versioning on the bucket (consider MFA Delete for critical data)."
    try:
        status = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    except (ClientError, BotoCoreError) as e:
        return _na(cid, title, bucket, sev, desc, rem, e)
    if status == "Enabled":
        return Finding(cid, title, "S3", bucket, PASS, sev, desc, rem, "Versioning: Enabled")
    return Finding(cid, title, "S3", bucket, WARNING, sev, desc, rem,
                   f"Versioning: {status or 'Never enabled'}")


# ---- S3-005: access logging ----------------------------------------------
def check_logging(s3, bucket):
    cid, title, sev = "S3-005", "Server access logging is enabled", LOW
    desc = "Access logs provide an audit trail for investigating suspicious access."
    rem = "Enable server access logging to a dedicated, access-restricted log bucket."
    try:
        enabled = s3.get_bucket_logging(Bucket=bucket).get("LoggingEnabled")
    except (ClientError, BotoCoreError) as e:
        return _na(cid, title, bucket, sev, desc, rem, e)
    if enabled:
        return Finding(cid, title, "S3", bucket, PASS, sev, desc, rem,
                       f"Logging to {enabled.get('TargetBucket')}/{enabled.get('TargetPrefix', '')}")
    return Finding(cid, title, "S3", bucket, WARNING, sev, desc, rem,
                   "Server access logging is not enabled.")


BUCKET_CHECKS = [check_public_access, check_block_public_access, check_encryption,
                 check_versioning, check_logging]


def run_s3_checks(bucket_names=None):
    """Run all S3 checks. If bucket_names is None, list buckets first."""
    s3 = get_client("s3")
    if bucket_names is None:
        try:
            bucket_names = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
        except (ClientError, BotoCoreError) as e:
            reason = _code(e) if isinstance(e, ClientError) else type(e).__name__
            return [not_assessed("S3-000", "S3 buckets could be listed", "S3", "(account)",
                                 HIGH, "Without listing buckets, no S3 check can run.",
                                 "Grant s3:ListAllMyBuckets.", reason)]
    findings = []
    for name in bucket_names:
        for check in BUCKET_CHECKS:
            findings.append(check(s3, name))
    return findings


if __name__ == "__main__":
    for f in run_s3_checks():
        print(f"{f.status:13} {f.severity:8} {f.check_id}  {f.resource:28} {f.evidence}")
