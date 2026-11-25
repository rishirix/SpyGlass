"""Unit test for IAM-005 comparison logic using a stub client (NOT real AWS data)."""
from datetime import datetime, timedelta, timezone

from spyglass.checks.iam_checks import check_access_key_age


class StubPaginator:
    def __init__(self, pages): self.pages = pages
    def paginate(self, **kw): return iter(self.pages)


class StubIAM:
    def get_paginator(self, op):
        old = datetime.now(timezone.utc) - timedelta(days=120)
        new = datetime.now(timezone.utc) - timedelta(days=10)
        return StubPaginator([{"AccessKeyMetadata": [
            {"AccessKeyId": "AKIAOLDKEY", "Status": "Active", "CreateDate": old},
            {"AccessKeyId": "AKIANEWKEY", "Status": "Active", "CreateDate": new},
            {"AccessKeyId": "AKIAINACTIV", "Status": "Inactive", "CreateDate": old},
        ]}])


for f in check_access_key_age(StubIAM(), ["test-user"]):
    print(f.status, f.resource, "-", f.evidence)
