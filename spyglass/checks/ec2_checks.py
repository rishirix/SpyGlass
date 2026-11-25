"""EC2 / EBS security checks. All calls are read-only."""
from botocore.exceptions import BotoCoreError, ClientError

from spyglass.aws_client import get_client
from spyglass.models import (Finding, PASS, FAIL, WARNING, CRITICAL, HIGH, MEDIUM, LOW,
                             not_assessed)

WORLD_V4 = "0.0.0.0/0"
WORLD_V6 = "::/0"


def _reason(e):
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "Unknown")
    return type(e).__name__


def _paginate(client, op, key, **kw):
    items = []
    for page in client.get_paginator(op).paginate(**kw):
        items.extend(page.get(key, []))
    return items


def _world_sources(perm):
    """CIDRs in this rule that are open to the whole internet."""
    out = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == WORLD_V4]
    out += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == WORLD_V6]
    return out


def _covers_port(perm, port):
    proto = perm.get("IpProtocol")
    if proto == "-1":
        return True
    if proto != "tcp":
        return False
    return perm.get("FromPort", 1) <= port <= perm.get("ToPort", 0)


def _covers_all_ports(perm):
    if perm.get("IpProtocol") == "-1":
        return True
    return perm.get("FromPort") == 0 and perm.get("ToPort") == 65535


def _sg_check(groups, cid, title, sev, desc, rem, matcher, what):
    out = []
    for g in groups:
        label = f"{g['GroupId']} ({g['GroupName']})"
        hits = []
        for perm in g.get("IpPermissions", []):
            if matcher(perm):
                hits += _world_sources(perm)
        if hits:
            out.append(Finding(cid, title, "EC2", label, FAIL, sev, desc, rem,
                               f"Ingress rule allows {what} from {', '.join(sorted(set(hits)))}"))
        else:
            out.append(Finding(cid, title, "EC2", label, PASS, sev, desc, rem,
                               f"No world-open rule allows {what}."))
    return out


def run_security_group_checks(ec2):
    specs = [
        ("EC2-001", "SSH (port 22) is not open to the internet", HIGH,
         "Open SSH invites brute-force and exploit attempts against your servers.",
         "Restrict port 22 to specific trusted IPs, or use SSM Session Manager instead of SSH.",
         lambda p: _covers_port(p, 22), "SSH (22)"),
        ("EC2-002", "RDP (port 3389) is not open to the internet", HIGH,
         "Open RDP is a common ransomware entry point.",
         "Restrict port 3389 to trusted IPs or a VPN/bastion host.",
         lambda p: _covers_port(p, 3389), "RDP (3389)"),
        ("EC2-003", "Security group does not allow all ports from the internet", CRITICAL,
         "Allowing all traffic exposes every service on attached instances.",
         "Remove the all-traffic rule and allow only the specific ports required.",
         _covers_all_ports, "all ports"),
    ]
    try:
        groups = _paginate(ec2, "describe_security_groups", "SecurityGroups")
    except (ClientError, BotoCoreError) as e:
        return [not_assessed(cid, title, "EC2", "(all security groups)", sev, desc, rem, _reason(e))
                for cid, title, sev, desc, rem, _, _ in specs]
    out = []
    for cid, title, sev, desc, rem, matcher, what in specs:
        out += _sg_check(groups, cid, title, sev, desc, rem, matcher, what)
    return out


# ---- EC2-004: EBS encryption ----------------------------------------------
def check_ebs_encryption(ec2):
    cid, title, sev = "EC2-004", "EBS volume is encrypted", MEDIUM
    desc = "Unencrypted volumes expose data if snapshots or disks are accessed outside the instance."
    rem = ("Create an encrypted copy of the volume (via snapshot) and replace it; "
           "enable EBS encryption by default for the region.")
    try:
        vols = _paginate(ec2, "describe_volumes", "Volumes")
    except (ClientError, BotoCoreError) as e:
        return [not_assessed(cid, title, "EC2", "(all volumes)", sev, desc, rem, _reason(e))]
    out = []
    for v in vols:
        res = v["VolumeId"]
        if v.get("Encrypted"):
            out.append(Finding(cid, title, "EC2", res, PASS, sev, desc, rem,
                               f"Encrypted ({v['Size']} GiB, {v['State']})."))
        else:
            out.append(Finding(cid, title, "EC2", res, FAIL, sev, desc, rem,
                               f"Not encrypted ({v['Size']} GiB, {v['State']})."))
    return out


# ---- EC2-005: public IP on instances --------------------------------------
def check_public_ips(ec2):
    cid, title, sev = "EC2-005", "Instance has no public IP address", LOW
    desc = ("Instances with public IPs are reachable from the internet. This is only "
            "risky combined with open security groups, so it is reported as a warning.")
    rem = "Place instances in private subnets and expose them via a load balancer or NAT where possible."
    try:
        reservations = _paginate(ec2, "describe_instances", "Reservations")
    except (ClientError, BotoCoreError) as e:
        return [not_assessed(cid, title, "EC2", "(all instances)", sev, desc, rem, _reason(e))]
    out = []
    for r in reservations:
        for i in r.get("Instances", []):
            if i.get("State", {}).get("Name") == "terminated":
                continue
            ip = i.get("PublicIpAddress")
            if ip:
                out.append(Finding(cid, title, "EC2", i["InstanceId"], WARNING, sev, desc, rem,
                                   f"Public IP {ip} (state: {i['State']['Name']})."))
            else:
                out.append(Finding(cid, title, "EC2", i["InstanceId"], PASS, sev, desc, rem,
                                   "No public IP address."))
    return out


def run_ec2_checks():
    ec2 = get_client("ec2")
    return run_security_group_checks(ec2) + check_ebs_encryption(ec2) + check_public_ips(ec2)


if __name__ == "__main__":
    for f in run_ec2_checks():
        print(f"{f.status:13} {f.severity:8} {f.check_id}  {f.resource:36} {f.evidence}")
