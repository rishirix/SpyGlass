# Spyglass: Automated AWS Security Assessment

A **read-only** AWS security auditor. It discovers resources, runs automated
misconfiguration checks through boto3, scores the result 0-100, stores scan history in
SQLite, and exports HTML/PDF reports. It never creates, changes or deletes AWS resources.

> **Demo vs live.** Without an AWS account, Spyglass runs in DEMO mode against the
> [moto](https://github.com/getmoto/moto) AWS emulator seeded with deliberately
> misconfigured resources. Demo results are NOT findings from a real account. The mode is
> shown in the UI, stored with every scan, and printed on every report.

## Features
- AWS connection check (STS), account ID and region display
- Discovery (paginated): S3 buckets, IAM users, IAM policies, EC2 instances,
  security groups, EBS volumes, CloudTrail trails
- 18 check types across S3, IAM, EC2 and CloudTrail
- Results: PASS / FAIL / WARNING / NOT ASSESSED, each with severity, evidence, risk
  explanation and remediation
- Risk score (weights Critical 10, High 7, Medium 4, Low 1); NOT ASSESSED is never a pass
- Dark dashboard with charts, findings filters, scan history, HTML and PDF reports

## Setup
```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

## Run in DEMO mode (no AWS account)
```bash
# terminal 1: emulator
moto_server -H 127.0.0.1 -p 5001
# terminal 2: seed it, then start the app
python seed_demo.py
python app.py            # http://127.0.0.1:5000
```
Then open **Run Assessment** and start a scan. Expected on the seeded environment:
score 55.6, 51 checks (24 pass, 20 fail, 7 warning, 0 not assessed).

## Run against a real AWS account (LIVE mode)
1. Create a **read-only IAM user** (never use root keys) with the policy in
   `docs/read-only-policy.json`.
2. Either set `SPYGLASS_MODE=live` in `.env` and configure credentials with
   `aws configure`, or use the **Connect to AWS** page.
3. Run a scan. Any `NOT ASSESSED` row with `AccessDenied` names a missing permission.

## Security design
- Read-only: only `List*`, `Get*`, `Describe*` calls
- Credentials never hardcoded, never written to disk or the database, never sent to the browser
- Form-supplied keys are held in server memory only; the server binds to 127.0.0.1
- Demo mode refuses any non-local endpoint
- Parameterized SQL, input validation, CSRF header guard, security headers, no debug mode
- AWS API errors handled; all list calls paginated

## Scoring
`score = 100 x (1 - penalty / max_points)` over assessed checks. FAIL = full severity
weight, WARNING = half, PASS = 0. NOT ASSESSED checks are excluded and reduce the
coverage figure.

## Tests
```bash
python tests_scoring.py     # scoring rules (fabricated findings)
python tests_key_age.py     # key-age logic (stub client)
python tests_denied.py      # AccessDenied -> NOT ASSESSED (stub client)
python tests_db.py          # SQLite round trip (needs moto running)
```
These stub-client tests use fabricated inputs and are unit tests, not scan results.

## Limitations
- One region per scan; S3 and IAM are global, EC2 and CloudTrail regional
- Admin rights via IAM groups or inline policies are not evaluated
- Only customer-managed IAM policies are inspected
- Moto does not reproduce every AWS behavior; no real account was scanned in development
- Not a replacement for AWS Security Hub, Config or Prowler
