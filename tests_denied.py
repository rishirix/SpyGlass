"""Unit test: AccessDenied must yield NOT ASSESSED, never PASS (stub client, NOT real AWS data)."""
from botocore.exceptions import ClientError

from spyglass.checks import cloudtrail_checks, ec2_checks, iam_checks, s3_checks
from spyglass.scoring import calculate_score


def denied(op):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, op)


class DenyAll:
    def __getattr__(self, name):
        def call(*a, **k):
            raise denied(name)
        return call

    def get_paginator(self, op):
        raise denied(op)


s3 = DenyAll()
results = [chk(s3, "some-bucket") for chk in s3_checks.BUCKET_CHECKS]
results += [iam_checks.check_root_mfa(DenyAll())]
results += iam_checks.check_user_mfa(DenyAll(), ["u1"])
results += ec2_checks.run_security_group_checks(DenyAll())
results += ec2_checks.check_ebs_encryption(DenyAll())
results += ec2_checks.check_public_ips(DenyAll())

for f in results:
    print(f"{f.status:13} {f.check_id}  {f.resource:24} {f.evidence}")

bad = [f for f in results if f.status != "NOT ASSESSED"]
assert not bad, f"{len(bad)} rows were not NOT ASSESSED: {[(f.check_id, f.status) for f in bad]}"
s = calculate_score(results)
assert s["score"] is None and s["coverage_pct"] == 0.0, s
print(f"\nall {len(results)} denied checks -> NOT ASSESSED; score={s['score']} ({s['rating']}), coverage={s['coverage_pct']}%")
