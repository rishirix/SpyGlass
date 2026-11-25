"""Demo-only patch: allow log delivery on the target bucket, then enable logging."""
import sys
from urllib.parse import urlparse

import boto3

import config

if config.MODE != "demo" or urlparse(config.MOTO_ENDPOINT).hostname not in ("127.0.0.1", "localhost"):
    sys.exit("Refusing: demo mode against a local endpoint only.")

s3 = boto3.client("s3", endpoint_url=config.MOTO_ENDPOINT, region_name="us-east-1",
                  aws_access_key_id="testing", aws_secret_access_key="testing")

s3.put_bucket_acl(Bucket="spyglass-demo-log-target", ACL="log-delivery-write")
s3.put_bucket_logging(
    Bucket="spyglass-demo-secure-data",
    BucketLoggingStatus={"LoggingEnabled": {
        "TargetBucket": "spyglass-demo-log-target", "TargetPrefix": "logs/"}},
)
print("ok - logging enabled on spyglass-demo-secure-data")
