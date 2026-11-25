from collections import Counter

from spyglass.checks import run_all_checks

results = run_all_checks()
print("total findings:", len(results))
for status, n in sorted(Counter(f.status for f in results).items()):
    print(f"  {status:13} {n}")
print()
for service in ["S3", "IAM", "EC2", "CloudTrail"]:
    print(f"  {service:11} {sum(1 for f in results if f.service == service)} rows")
