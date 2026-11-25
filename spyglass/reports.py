"""HTML and PDF report generation from a saved scan."""
import io
from datetime import datetime

from flask import render_template

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ST_ORDER = {"FAIL": 0, "WARNING": 1, "NOT ASSESSED": 2, "PASS": 3}


def build_context(scan: dict, pdf: bool = False) -> dict:
    findings = sorted(scan["findings"],
                      key=lambda f: (ST_ORDER.get(f["status"], 9), SEV_ORDER.get(f["severity"], 9), f["check_id"]))
    issues = [f for f in findings if f["status"] in ("FAIL", "WARNING", "NOT ASSESSED")]
    sev = {s: sum(1 for f in findings if f["status"] == "FAIL" and f["severity"] == s) for s in SEV_ORDER}
    return {"scan": scan, "findings": findings, "issues": issues, "sev_counts": sev,
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M"), "pdf": pdf}


def render_html(scan: dict) -> str:
    return render_template("report_template.html", **build_context(scan))


def render_pdf(scan: dict) -> bytes:
    from xhtml2pdf import pisa  # imported lazily so the app starts without it
    html = render_template("report_template.html", **build_context(scan, pdf=True))
    buf = io.BytesIO()
    result = pisa.CreatePDF(html, dest=buf)
    if result.err:
        raise RuntimeError("PDF generation failed")
    return buf.getvalue()
