"""Seed the local moto emulator with a deliberately misconfigured environment.

DEMO MODE ONLY. Refuses to run against anything but a local endpoint.
Run:  python seed_demo.py
"""
import json
import sys
from urllib.parse import urlparse

import boto3

import config

if config.MODE != "demo" or urlparse(config.MOTO_ENDPOINT).hostname not in ("127.0.0.1", "localhost"):
    sys.exit("Refusing to seed: this script only runs in demo mode against a local endpoint.")

EP = config.MOTO_ENDPOINT


def client(service):
    return boto3.client(
        service, endpoint_url=EP, region_name="us-east-1",
        aws_access_key_id="testing", aws_secret_access_key="testing",
    )


s3, iam, ec2, ct = client("s3"), client("iam"), client("ec2"), client("cloudtrail")


def safe(label, fn):
    try:
        fn()
        print("ok   ", label)
    except Exception as e:  # keep seeding even if one item fails
        print("FAIL ", label, "->", type(e).__name__, e)


# ---------------------------------------------------------------- S3 ----
def s3_setup():
    # Insecure bucket: public ACL, no encryption/versioning/logging
    s3.create_bucket(Bucket="spyglass-demo-public-data")
    s3.put_bucket_acl(Bucket="spyglass-demo-public-data", ACL="public-read")

    # Well-configured bucket
    s3.create_bucket(Bucket="spyglass-demo-secure-data")
    s3.put_public_access_block(
        Bucket="spyglass-demo-secure-data",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="spyglass-demo-secure-data",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(
        Bucket="spyglass-demo-secure-data",
        VersioningConfiguration={"Status": "Enabled"},
    )
    s3.create_bucket(Bucket="spyglass-demo-log-target")
    s3.put_bucket_acl(Bucket="spyglass-demo-log-target", ACL="log-delivery-write")
    s3.put_bucket_logging(
        Bucket="spyglass-demo-secure-data",
        BucketLoggingStatus={"LoggingEnabled": {
            "TargetBucket": "spyglass-demo-log-target", "TargetPrefix": "logs/"}},
    )


# --------------------------------------------------------------- IAM ----
ADMIN_POLICY = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "*", "Resource": "*"}]}
READONLY_POLICY = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["s3:GetObject"],
     "Resource": "arn:aws:s3:::spyglass-demo-secure-data/*"}]}


def iam_setup():
    # alice: no MFA, admin, access key (made old in the next step)
    iam.create_user(UserName="alice-admin")
    iam.create_access_key(UserName="alice-admin")
    p = iam.create_policy(PolicyName="AdminFullAccess", PolicyDocument=json.dumps(ADMIN_POLICY))
    iam.attach_user_policy(UserName="alice-admin", PolicyArn=p["Policy"]["Arn"])

    # bob: has MFA, limited permissions
    iam.create_user(UserName="bob-dev")
    q = iam.create_policy(PolicyName="ReadSecureBucket", PolicyDocument=json.dumps(READONLY_POLICY))
    iam.attach_user_policy(UserName="bob-dev", PolicyArn=q["Policy"]["Arn"])
    m = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob-mfa")
    iam.enable_mfa_device(
        UserName="bob-dev", SerialNumber=m["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456", AuthenticationCode2="654321",
    )


# --------------------------------------------------------------- EC2 ----
def ec2_setup():
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    subnet = ec2.describe_subnets()["Subnets"][0]["SubnetId"]

    sg_ssh = ec2.create_security_group(GroupName="open-ssh", Description="SSH open to world", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg_ssh, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    sg_rdp = ec2.create_security_group(GroupName="open-rdp", Description="RDP open to world", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg_rdp, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    sg_all = ec2.create_security_group(GroupName="open-all", Description="All ports open", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg_all, IpPermissions=[
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    sg_ok = ec2.create_security_group(GroupName="internal-https", Description="HTTPS from VPC only", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg_ok, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}])

    # Instance with a public IP
    ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro",
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet,
                            "AssociatePublicIpAddress": True, "Groups": [sg_ssh]}],
    )

    # EBS: one unencrypted, one encrypted
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=False)
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)


# -------------------------------------------------------- CloudTrail ----
def ct_setup():
    # Trail exists but: not logging, no log file validation
    s3.create_bucket(Bucket="spyglass-demo-trail-logs")
    ct.create_trail(Name="spyglass-demo-trail", S3BucketName="spyglass-demo-trail-logs",
                    EnableLogFileValidation=False)


safe("s3 buckets", s3_setup)
safe("iam users/policies", iam_setup)
safe("ec2 resources", ec2_setup)
safe("cloudtrail", ct_setup)
print("\nSeeding done. Next: python -m spyglass.discovery")
