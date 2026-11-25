"""DEMO ONLY: fix seeded misconfigurations in the moto emulator, in stages.
Usage: python remediate_demo.py 1|2|3   (run stages in order, rescan after each)
"""
import sys
from urllib.parse import urlparse

import boto3

import config

if config.MODE != "demo" or urlparse(config.MOTO_ENDPOINT).hostname not in ("127.0.0.1", "localhost"):
    sys.exit("Refusing: demo mode against a local endpoint only.")

stage = sys.argv[1] if len(sys.argv) > 1 else ""
kw = dict(endpoint_url=config.MOTO_ENDPOINT, region_name="us-east-1",
          aws_access_key_id="testing", aws_secret_access_key="testing")
ec2, ct, s3 = (boto3.client(x, **kw) for x in ("ec2", "cloudtrail", "s3"))


def step(label, fn):
    try:
        fn()
        print("ok  ", label)
    except Exception as e:
        print("FAIL", label, "->", type(e).__name__, e)


def close_sg(name):
    g = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [name]}])["SecurityGroups"][0]
    ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])


if stage == "1":      # close world-open security groups
    for n in ("open-ssh", "open-rdp", "open-all"):
        step(f"revoke open ingress on {n}", lambda n=n: close_sg(n))

elif stage == "2":    # CloudTrail
    step("start logging", lambda: ct.start_logging(Name="spyglass-demo-trail"))
    step("enable log file validation",
         lambda: ct.update_trail(Name="spyglass-demo-trail", EnableLogFileValidation=True))

elif stage == "3":    # harden the public bucket
    b = "spyglass-demo-public-data"
    step("make bucket ACL private", lambda: s3.put_bucket_acl(Bucket=b, ACL="private"))
    step("enable block public access", lambda: s3.put_public_access_block(
        Bucket=b, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True}))
    step("enable default encryption", lambda: s3.put_bucket_encryption(
        Bucket=b, ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}))
    step("enable versioning", lambda: s3.put_bucket_versioning(
        Bucket=b, VersioningConfiguration={"Status": "Enabled"}))
    step("enable access logging", lambda: s3.put_bucket_logging(
        Bucket=b, BucketLoggingStatus={"LoggingEnabled": {
            "TargetBucket": "spyglass-demo-log-target", "TargetPrefix": "public-data/"}}))
else:
    sys.exit("Usage: python remediate_demo.py 1|2|3")
