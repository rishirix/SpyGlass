from spyglass import database as db
from spyglass.aws_client import verify_connection
from spyglass.checks import run_all_checks
from spyglass.discovery import discover_all
from spyglass.scoring import calculate_score

conn = verify_connection()
assert conn["connected"], conn
disc = discover_all()
counts = {k: v["count"] for k, v in disc.items()}
findings = run_all_checks()
score = calculate_score(findings)

sid = db.save_scan(conn, counts, score, findings)
print("saved scan id:", sid)

s = db.get_scan(sid)
print("mode:", s["mode"], "| account:", s["account_id"], "| score:", s["score"])
print("findings stored:", len(s["findings"]), "(expect", len(findings), ")")
print("resource counts:", s["resource_counts"])
print("history rows:", len(db.list_scans()))

try:
    db.get_scan("1 OR 1=1")
except ValueError:
    print("injection-style id rejected (ValueError)")
print("missing scan:", db.get_scan(99999))
