"""Read-only AWS resource discovery.

Each resource type is discovered independently. If a call fails (e.g.
AccessDenied) that type is reported with status NOT_ASSESSED and an error,
never as "0 resources". All list calls use paginators.
"""
from botocore.exceptions import BotoCoreError, ClientError

from spyglass.aws_client import AWSConnectionError, get_client

ACCESS_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                       "UnauthorizedAccess", "AuthorizationError"}


def _error_info(exc: Exception) -> dict:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        status = "ACCESS_DENIED" if code in ACCESS_DENIED_CODES else "ERROR"
        return {"status": status, "error": f"{code}"}
    if isinstance(exc, AWSConnectionError):
        return {"status": "ERROR", "error": exc.code}
    return {"status": "ERROR", "error": type(exc).__name__}


def _paginate(client, op: str, key: str, **kwargs) -> list:
    items = []
    for page in client.get_paginator(op).paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def _guard(fn):
    """Run a discovery function; convert failures into a NOT_ASSESSED entry."""
    try:
        items = fn()
        return {"status": "OK", "count": len(items), "items": items, "error": None}
    except (ClientError, BotoCoreError, AWSConnectionError) as e:
        info = _error_info(e)
        return {"status": info["status"], "count": None, "items": [], "error": info["error"]}


def discover_s3_buckets():
    s3 = get_client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    return [{"name": b["Name"], "created": b["CreationDate"].isoformat()} for b in buckets]


def discover_iam_users():
    iam = get_client("iam")
    users = _paginate(iam, "list_users", "Users")
    return [{"name": u["UserName"], "arn": u["Arn"],
             "created": u["CreateDate"].isoformat()} for u in users]


def discover_iam_policies():
    """Customer-managed policies only (Scope=Local); AWS-managed ones are not ours to fix."""
    iam = get_client("iam")
    pols = _paginate(iam, "list_policies", "Policies", Scope="Local")
    return [{"name": p["PolicyName"], "arn": p["Arn"],
             "attachment_count": p.get("AttachmentCount", 0),
             "default_version": p.get("DefaultVersionId")} for p in pols]


def discover_ec2_instances():
    ec2 = get_client("ec2")
    out = []
    for r in _paginate(ec2, "describe_instances", "Reservations"):
        for i in r.get("Instances", []):
            out.append({
                "id": i["InstanceId"],
                "type": i.get("InstanceType"),
                "state": i.get("State", {}).get("Name"),
                "public_ip": i.get("PublicIpAddress"),
                "security_groups": sorted(
                    {g["GroupId"] for g in i.get("SecurityGroups", [])}
                    | {g["GroupId"] for n in i.get("NetworkInterfaces", [])
                       for g in n.get("Groups", [])}),
            })
    return out


def discover_security_groups():
    ec2 = get_client("ec2")
    sgs = _paginate(ec2, "describe_security_groups", "SecurityGroups")
    return [{"id": g["GroupId"], "name": g["GroupName"], "vpc_id": g.get("VpcId"),
             "description": g.get("Description")} for g in sgs]


def discover_ebs_volumes():
    ec2 = get_client("ec2")
    vols = _paginate(ec2, "describe_volumes", "Volumes")
    return [{"id": v["VolumeId"], "size_gb": v["Size"], "encrypted": v.get("Encrypted", False),
             "state": v["State"]} for v in vols]


def discover_cloudtrail_trails():
    ct = get_client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    return [{"name": t["Name"], "arn": t.get("TrailARN"),
             "multi_region": t.get("IsMultiRegionTrail", False)} for t in trails]


DISCOVERERS = {
    "S3 Buckets": discover_s3_buckets,
    "IAM Users": discover_iam_users,
    "IAM Policies": discover_iam_policies,
    "EC2 Instances": discover_ec2_instances,
    "Security Groups": discover_security_groups,
    "EBS Volumes": discover_ebs_volumes,
    "CloudTrail Trails": discover_cloudtrail_trails,
}


def discover_all() -> dict:
    """Return {resource_type: {status, count, items, error}} for all types."""
    return {name: _guard(fn) for name, fn in DISCOVERERS.items()}


if __name__ == "__main__":
    for name, res in discover_all().items():
        shown = res["count"] if res["status"] == "OK" else f"NOT ASSESSED ({res['error']})"
        print(f"{name:20} {shown}")
        for item in res["items"]:
            print("    -", item)
