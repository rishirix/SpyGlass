"""Spyglass Flask application: read-only AWS security auditor."""
import threading

from flask import Flask, Response, jsonify, render_template, request
from jinja2 import TemplateNotFound

import config
from spyglass import aws_client, database
from spyglass.checks import run_all_checks
from spyglass.discovery import discover_all
from spyglass import reports
from spyglass.scoring import calculate_score

app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # small request bodies only

_scan_lock = threading.Lock()
database.init_db()


# ------------------------------------------------------------ security --
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net")
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _post_guard():
    """CSRF defence: POSTs must be JSON with a custom header."""
    if request.headers.get("X-Requested-With") != "Spyglass":
        return jsonify(error="Missing required header."), 403
    if not request.is_json:
        return jsonify(error="JSON body required."), 415
    return None


def _page(name, **ctx):
    try:
        return render_template(name, mode=aws_client.get_mode(), **ctx)
    except TemplateNotFound:
        return (f"<h3>Spyglass</h3><p>Template <code>{name}</code> is not written yet "
                f"(Step 13). The JSON API is live: <a href='/api/status'>/api/status</a></p>")


# --------------------------------------------------------------- pages --
def _diff(prev, cur):
    """Compare two saved scans. Returns None if they are not comparable."""
    if prev["mode"] != cur["mode"] or prev["account_id"] != cur["account_id"]:
        return None
    key = lambda f: (f["check_id"], f["resource"])
    old = {key(f): f for f in prev["findings"]}
    new = {key(f): f for f in cur["findings"]}
    changed = [{"check_id": k[0], "resource": k[1], "title": f["title"],
                "before": old[k]["status"], "after": f["status"]}
               for k, f in new.items() if k in old and old[k]["status"] != f["status"]]
    added = [{"check_id": k[0], "resource": k[1], "status": f["status"]}
             for k, f in new.items() if k not in old]
    removed = [{"check_id": k[0], "resource": k[1], "status": f["status"]}
               for k, f in old.items() if k not in new]
    delta = None
    if prev["score"] is not None and cur["score"] is not None:
        delta = round(cur["score"] - prev["score"], 1)
    return {"prev_id": prev["id"], "prev_score": prev["score"], "delta": delta,
            "changed": changed, "added": added, "removed": removed}


@app.get("/")
def dashboard():
    scans = database.list_scans(2)
    if not scans:
        return _page("dashboard.html", scan=None, diff=None)
    cur = database.get_scan(scans[0]["id"])
    diff = _diff(database.get_scan(scans[1]["id"]), cur) if len(scans) > 1 else None
    return _page("dashboard.html", scan=cur, diff=diff)


@app.get("/inventory")
def inventory_page():
    return _page("inventory.html")


@app.get("/assessment")
def assessment_page():
    return _page("assessment.html")


@app.get("/findings")
def findings_page():
    return _page("findings.html", scans=database.list_scans(50))


@app.get("/reports")
def reports_page():
    return _page("reports.html", scans=database.list_scans(50))


@app.get("/history")
def history_page():
    return _page("history.html", scans=database.list_scans(50))


@app.get("/connect")
def connect_page():
    return _page("connect.html")


# ----------------------------------------------------------------- API --
@app.get("/api/status")
def api_status():
    state = aws_client.describe_state()
    conn = aws_client.verify_connection()
    return jsonify(state=state, connection=conn)


@app.post("/api/connect")
def api_connect():
    blocked = _post_guard()
    if blocked:
        return blocked
    data = request.get_json(silent=True) or {}
    previous_mode = aws_client.get_mode()
    try:
        aws_client.set_credentials(data.get("access_key_id"), data.get("secret_access_key"),
                                   data.get("region"), data.get("session_token"))
    except aws_client.AWSConnectionError as e:
        return jsonify(error=e.message, code=e.code), 400  # mode untouched
    aws_client.set_mode("live")
    conn = aws_client.verify_connection()
    if not conn["connected"]:
        aws_client.clear_credentials()  # do not keep credentials that failed
        aws_client.set_mode(previous_mode)  # roll back
        return jsonify(connection=conn), 401
    return jsonify(connection=conn)


@app.post("/api/disconnect")
def api_disconnect():
    blocked = _post_guard()
    if blocked:
        return blocked
    aws_client.clear_credentials()
    return jsonify(state=aws_client.describe_state())


@app.post("/api/mode")
def api_mode():
    blocked = _post_guard()
    if blocked:
        return blocked
    data = request.get_json(silent=True) or {}
    try:
        aws_client.set_mode(data.get("mode"))
    except aws_client.AWSConnectionError as e:
        return jsonify(error=e.message, code=e.code), 400
    return jsonify(state=aws_client.describe_state())


@app.post("/api/scan")
def api_scan():
    blocked = _post_guard()
    if blocked:
        return blocked
    if not _scan_lock.acquire(blocking=False):
        return jsonify(error="A scan is already running."), 409
    try:
        conn = aws_client.verify_connection()
        if not conn["connected"]:
            return jsonify(error=conn["error"], code=conn["error_code"]), 400
        disc = discover_all()
        counts = {k: v["count"] for k, v in disc.items()}  # None = not assessed
        findings = run_all_checks()
        score = calculate_score(findings)
        scan_id = database.save_scan(conn, counts, score, findings)
        return jsonify(scan=database.get_scan(scan_id))
    finally:
        _scan_lock.release()


@app.get("/api/scans")
def api_scans():
    return jsonify(scans=database.list_scans(50))


@app.get("/api/scans/<int:scan_id>")
def api_scan_detail(scan_id):
    scan = database.get_scan(scan_id)
    if scan is None:
        return jsonify(error="Scan not found."), 404
    return jsonify(scan=scan)


@app.get("/api/inventory")
def api_inventory():
    conn = aws_client.verify_connection()
    if not conn["connected"]:
        return jsonify(error=conn["error"], code=conn["error_code"]), 400
    return jsonify(connection=conn, inventory=discover_all())


@app.get("/report/<int:scan_id>.html")
def report_html(scan_id):
    scan = database.get_scan(scan_id)
    if scan is None:
        return jsonify(error="Scan not found."), 404
    return Response(reports.render_html(scan), mimetype="text/html",
                    headers={"Content-Disposition": f"attachment; filename=spyglass-report-{scan_id}.html"})


@app.get("/report/<int:scan_id>.pdf")
def report_pdf(scan_id):
    scan = database.get_scan(scan_id)
    if scan is None:
        return jsonify(error="Scan not found."), 404
    try:
        pdf = reports.render_pdf(scan)
    except (ImportError, RuntimeError):
        return jsonify(error="PDF generation is unavailable on this machine."), 500
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=spyglass-report-{scan_id}.pdf"})


if __name__ == "__main__":
    # 127.0.0.1 only; debug OFF (the Flask debugger allows remote code execution).
    app.run(host="127.0.0.1", port=5000, debug=False)
