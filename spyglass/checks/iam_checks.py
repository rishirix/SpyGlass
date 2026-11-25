"""IAM security checks. All calls are read-only."""
import json
from datetime import datetime, timezone
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError

import config
from spyglass.aws_client import get_client
from spyglass.models import (Finding, PASS, FAIL, HIGH, MEDIUM, CRITICAL, not_assessed)


def _code(e):
    return e.response.get("Error", {}).get("Code", "Unknown")


def _reason(e):
    return _code(e) if isinstance(e, ClientError) else type(e).__name__


def _paginate(client, op, key, **kw):
    items = []
    for page in client.get_paginator(op).paginate(**kw):
        items.extend(page.get(key, []))
    return items


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _normalize_doc(doc):
    if isinstance(doc, dict):
        return doc
    return json.loads(unquote(doc))


def policy_wildcards(doc):
    """Return (wildcard_action, wildcard_resource) found in any Allow statement."""
    doc = _normalize_doc(doc)
    wa = wr = False
    for st in _as_list(doc.get("Statement", [])):
        if st.get("Effect") != "Allow":
            continue
        actions = _as_list(st.get("Action", []))
        resources = _as_list(st.get("Resource", []))
        if any(a == "*" for a in actions):
            wa = True
        if any(r == "*" for r in resources):
            wr = True
    return wa, wr


def _policy_document(iam, arn):
    meta = iam.get_policy(PolicyArn=arn)["Policy"]
    ver = iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])
    return ver["PolicyVersion"]["Document"]


# ---- IAM-001: root MFA ---------------------------------------------------
def check_root_mfa(iam):
    cid, title, sev = "IAM-001", "Root account has MFA enabled", CRITICAL
    desc = ("The root user has unrestricted control of the account. Without MFA, a "
            "leaked password alone gives an attacker full access.")
    rem = "Sign in as root and enable a hardware or virtual MFA device. Never create root access keys."
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
    except (ClientError, BotoCoreError) as e:
        return not_assessed(cid, title, "IAM", "root account", sev, desc, rem, _reason(e))
    if "AccountMFAEnabled" not in summary:
        return not_assessed(cid, title, "IAM", "root account", sev, desc, rem,
                            "AccountMFAEnabled not present in account summary")
    if summary["AccountMFAEnabled"] == 1:
        return Finding(cid, title, "IAM", "root account", PASS, sev, desc, rem, "Root MFA is enabled.")
    return Finding(cid, title, "IAM", "root account", FAIL, sev, desc, rem, "Root MFA is NOT enabled.")


# ---- IAM-002: user MFA ---------------------------------------------------
def check_user_mfa(iam, users):
    cid, title, sev = "IAM-002", "IAM user has MFA enabled", HIGH
    desc = "Users without MFA are vulnerable to credential theft and phishing."
    rem = "Enforce MFA for every IAM user (or move people to IAM Identity Center)."
    out = []
    for u in users:
        try:
            devices = _paginate(iam, "list_mfa_devices", "MFADevices", UserName=u)
        except (ClientError, BotoCoreError) as e:
            out.append(not_assessed(cid, title, "IAM", u, sev, desc, rem, _reason(e)))
            continue
        if devices:
            out.append(Finding(cid, title, "IAM", u, PASS, sev, desc, rem,
                               f"{len(devices)} MFA device(s) registered."))
        else:
            out.append(Finding(cid, title, "IAM", u, FAIL, sev, desc, rem, "No MFA device registered."))
    return out


# ---- IAM-003: wildcard policies ------------------------------------------
def check_wildcard_policies(iam, policies):
    cid, title, sev = "IAM-003", "Policy avoids wildcard permissions", HIGH
    desc = ("Wildcard actions or resources violate least privilege; a compromised "
            "identity with such a policy can do far more than intended.")
    rem = "Replace '*' with the specific actions and resource ARNs actually required."
    out = []
    for arn, name in policies:
        try:
            wa, wr = policy_wildcards(_policy_document(iam, arn))
        except (ClientError, BotoCoreError, ValueError) as e:
            out.append(not_assessed(cid, title, "IAM", name, sev, desc, rem, _reason(e)))
            continue
        if wa or wr:
            found = [x for x, f in (("Action: *", wa), ("Resource: *", wr)) if f]
            out.append(Finding(cid, title, "IAM", name, FAIL, sev, desc, rem,
                               "Allow statement with " + " and ".join(found)))
        else:
            out.append(Finding(cid, title, "IAM", name, PASS, sev, desc, rem, "No wildcard Allow statements."))
    return out


# ---- IAM-004: admin users ------------------------------------------------
def check_admin_users(iam, users):
    cid, title, sev = "IAM-004", "User lacks full administrative privileges", HIGH
    desc = "Users with Action:* on Resource:* can do anything in the account."
    rem = "Grant least-privilege permissions; limit admin access to a few break-glass roles."
    out = []
    for u in users:
        try:
            attached = _paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=u)
            admin_via = []
            for p in attached:
                wa, wr = policy_wildcards(_policy_document(iam, p["PolicyArn"]))
                if wa and wr:
                    admin_via.append(p["PolicyName"])
        except (ClientError, BotoCoreError, ValueError) as e:
            out.append(not_assessed(cid, title, "IAM", u, sev, desc, rem, _reason(e)))
            continue
        if admin_via:
            out.append(Finding(cid, title, "IAM", u, FAIL, sev, desc, rem,
                               "Full admin via attached policy: " + ", ".join(admin_via)))
        else:
            out.append(Finding(cid, title, "IAM", u, PASS, sev, desc, rem,
                               "No directly attached full-admin policy (group/inline not checked)."))
    return out


# ---- IAM-005: access key age ---------------------------------------------
def check_access_key_age(iam, users):
    cid, title, sev = "IAM-005", "Access keys are rotated within policy limit", MEDIUM
    limit = config.ACCESS_KEY_MAX_AGE_DAYS
    desc = (f"Long-lived keys increase exposure if leaked. Policy threshold: {limit} days "
            "(configurable via ACCESS_KEY_MAX_AGE_DAYS).")
    rem = "Rotate the key, then deactivate and delete the old one. Prefer IAM roles over long-lived keys."
    now = datetime.now(timezone.utc)
    out = []
    for u in users:
        try:
            keys = _paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=u)
        except (ClientError, BotoCoreError) as e:
            out.append(not_assessed(cid, title, "IAM", u, sev, desc, rem, _reason(e)))
            continue
        active = [k for k in keys if k.get("Status") == "Active"]
        if not active:
            out.append(Finding(cid, title, "IAM", u, PASS, sev, desc, rem, "No active access keys."))
            continue
        for k in active:
            age = (now - k["CreateDate"]).days
            res = f"{u} ({k['AccessKeyId']})"
            if age > limit:
                out.append(Finding(cid, title, "IAM", res, FAIL, sev, desc, rem,
                                   f"Key is {age} days old (limit {limit})."))
            else:
                out.append(Finding(cid, title, "IAM", res, PASS, sev, desc, rem,
                                   f"Key is {age} days old (limit {limit})."))
    return out


def run_iam_checks():
    iam = get_client("iam")
    findings = [check_root_mfa(iam)]
    try:
        users = [u["UserName"] for u in _paginate(iam, "list_users", "Users")]
    except (ClientError, BotoCoreError) as e:
        findings.append(not_assessed("IAM-002", "IAM users could be listed", "IAM", "(account)",
                                     HIGH, "Without listing users, per-user checks cannot run.",
                                     "Grant iam:ListUsers.", _reason(e)))
        users = []
    try:
        policies = [(p["Arn"], p["PolicyName"]) for p in _paginate(iam, "list_policies", "Policies", Scope="Local")]
    except (ClientError, BotoCoreError) as e:
        findings.append(not_assessed("IAM-003", "IAM policies could be listed", "IAM", "(account)",
                                     HIGH, "Without listing policies, wildcard checks cannot run.",
                                     "Grant iam:ListPolicies.", _reason(e)))
        policies = []
    findings += check_user_mfa(iam, users)
    findings += check_wildcard_policies(iam, policies)
    findings += check_admin_users(iam, users)
    findings += check_access_key_age(iam, users)
    return findings


if __name__ == "__main__":
    for f in run_iam_checks():
        print(f"{f.status:13} {f.severity:8} {f.check_id}  {f.resource:34} {f.evidence}")
