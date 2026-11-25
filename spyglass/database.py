"""SQLite storage for scan history. All queries are parameterized."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT NOT NULL,
    mode TEXT NOT NULL,
    account_id TEXT,
    region TEXT,
    score REAL,
    rating TEXT,
    coverage_pct REAL,
    total_checks INTEGER,
    passed INTEGER,
    failed INTEGER,
    warnings INTEGER,
    not_assessed INTEGER,
    critical_findings INTEGER,
    high_findings INTEGER,
    resource_counts TEXT,
    method TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id TEXT, title TEXT, service TEXT, resource TEXT,
    status TEXT, severity TEXT, description TEXT, remediation TEXT, evidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


@contextmanager
def _conn():
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(config.DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db():
    with _conn() as con:
        con.executescript(SCHEMA)


def save_scan(connection: dict, resource_counts: dict, score: dict, findings) -> int:
    """Store one scan and its findings atomically. Returns the scan id."""
    init_db()
    with _conn() as con:
        cur = con.execute(
            """INSERT INTO scans (scanned_at, mode, account_id, region, score, rating,
               coverage_pct, total_checks, passed, failed, warnings, not_assessed,
               critical_findings, high_findings, resource_counts, method)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             connection.get("mode"), connection.get("account_id"), connection.get("region"),
             score["score"], score["rating"], score["coverage_pct"], score["total_checks"],
             score["passed"], score["failed"], score["warnings"], score["not_assessed"],
             score["critical_findings"], score["high_findings"],
             json.dumps(resource_counts), score["method"]),
        )
        scan_id = cur.lastrowid
        con.executemany(
            """INSERT INTO findings (scan_id, check_id, title, service, resource, status,
               severity, description, remediation, evidence) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            [(scan_id, f.check_id, f.title, f.service, f.resource, f.status, f.severity,
              f.description, f.remediation, f.evidence) for f in findings],
        )
        return scan_id


def list_scans(limit=50):
    limit = max(1, min(int(limit), 500))
    with _conn() as con:
        rows = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_scan_dict(r) for r in rows]


def get_scan(scan_id: int):
    with _conn() as con:
        row = con.execute("SELECT * FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
        if row is None:
            return None
        fr = con.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY id",
                         (int(scan_id),)).fetchall()
    scan = _scan_dict(row)
    scan["findings"] = [dict(r) for r in fr]
    return scan


def delete_scan(scan_id: int) -> bool:
    with _conn() as con:
        cur = con.execute("DELETE FROM scans WHERE id = ?", (int(scan_id),))
        return cur.rowcount > 0


def _scan_dict(row):
    d = dict(row)
    d["resource_counts"] = json.loads(d["resource_counts"] or "{}")
    return d
