"""Flask entry point for complete-only URL security analysis."""

import os
import secrets

from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from analyzer.detection_manager import run_all_checks
from analyzer.exceptions import AnalysisIncompleteError
from analyzer.pdf_generator import generate_pdf
from analyzer.risk_engine import calculate_posture, calculate_risk
from analyzer.scoring_policy import load_scoring_policy
from analyzer.url_validator import get_last_validation_result, validate_url_input
from database.database import (
    clear_history,
    create_database,
    delete_scan,
    get_all_scans,
    get_average_risk,
    get_highest_risk,
    get_lowest_risk,
    get_total_scans,
    save_scan,
)


load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def env_flag(name, default=False):
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=16 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=env_flag("SESSION_COOKIE_SECURE", False),
    SESSION_COOKIE_NAME="url_security_session",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)
create_database()

# Kept as an app-level name for route and test compatibility. Outbound HTTP
# still passes through the stricter safe request layer.
is_valid_url = validate_url_input


@app.after_request
def add_security_headers(response):
    response.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": (
            "default-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; img-src 'self' data:; "
            "script-src 'self'; style-src 'self' 'unsafe-inline'"
        ),
    })
    return response


def get_history_session_id():
    session.permanent = True
    value = session.get("history_session_id")
    if not value:
        value = uuid4().hex
        session["history_session_id"] = value
    return value


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token():
    submitted = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    if not submitted or not expected or not secrets.compare_digest(submitted, expected):
        abort(400, description="Invalid or missing CSRF token.")


app.jinja_env.globals["csrf_token"] = get_csrf_token


def get_report_path(filename):
    return REPORTS_DIR / os.path.basename(filename)


def remove_previous_report():
    filename = session.pop("report_filename", None)
    if not filename:
        return
    path = get_report_path(filename)
    if path.exists():
        try:
            path.unlink()
        except OSError:
            pass


def default_scan_status():
    return {
        "mode": "complete",
        "label": "Complete Analysis",
        "complete": True,
        "network_available": True,
        "code": "public_target",
        "message": "All required checks completed.",
    }


def default_content_warning():
    return {
        "show": False,
        "type": None,
        "icon": None,
        "title": "No content warning detected",
        "message": "No sensitive content category was identified.",
    }


def _section(results, name):
    value = results.get(name, {})
    return value if isinstance(value, dict) else {}


def build_report_data(url, results, risk_score, verdict, reasons, posture, policy):
    https = _section(results, "https")
    ip_address = _section(results, "ip_address")
    keywords = _section(results, "keywords")
    length = _section(results, "url_length")
    subdomains = _section(results, "subdomains")
    at_symbol = _section(results, "at_symbol")
    shortener = _section(results, "shortener")
    hyphens = _section(results, "hyphens")
    tld = _section(results, "tld")

    return {
        "url": url,
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons,
        "scan_status": results.get("scan_status", default_scan_status()),
        "network_status": _section(results, "network_status"),
        "content_warning": results.get("content_warning", default_content_warning()),
        "posture": posture,
        "engine_version": policy["engine_version"],
        "policy_version": policy["policy_version"],
        "https_status": https.get("status", "Not checked"),
        "ip_status": ip_address.get("status", "Not checked"),
        "keyword_count": keywords.get("count", 0),
        "keywords": keywords.get("matches", []),
        "url_length": length.get("length", 0),
        "length_category": length.get("status", "Not checked"),
        "subdomain_count": subdomains.get("count", 0),
        "subdomain_status": subdomains.get("status", "Not checked"),
        "at_status": at_symbol.get("status", "Not checked"),
        "shortener_status": shortener.get("status", "Not checked"),
        "hyphen_count": hyphens.get("count", 0),
        "hyphen_status": hyphens.get("status", "Not checked"),
        "domain_age": _section(results, "domain_age"),
        "tld": tld.get("value", "Unknown"),
        "tld_status": tld.get("status", "Not checked"),
        "whois": _section(results, "whois"),
        "dns": _section(results, "dns"),
        "ssl": _section(results, "ssl"),
        "analysis_results": results,
    }


def create_pdf(report_data):
    filename = f"security_report_{uuid4().hex}.pdf"
    path = get_report_path(filename)
    try:
        generate_pdf(report_data, str(path))
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError("PDF generator did not create a report file.")
    except Exception as error:
        app.logger.exception("PDF report generation failed: %s", error)
        session.pop("report_filename", None)
        return False
    session["report_filename"] = filename
    return True


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    url = request.form.get("url", "").strip()
    if not url:
        return render_template("index.html", error="Please enter a URL.", entered_url=url)
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    if not is_valid_url(url):
        validation = get_last_validation_result()
        return render_template(
            "index.html",
            error=validation.get("message", "Please enter a valid public HTTP or HTTPS URL."),
            entered_url=url,
        )

    history_session_id = get_history_session_id()
    remove_previous_report()
    try:
        results = run_all_checks(url)
        risk_score, verdict, reasons = calculate_risk(results)
    except AnalysisIncompleteError as error:
        return render_template(
            "analysis_error.html",
            url=url,
            message=error.message,
            failed_checks=error.failed_checks,
        ), 503

    posture = calculate_posture(results)
    policy = load_scoring_policy()
    report_data = build_report_data(
        url, results, risk_score, verdict, reasons, posture, policy
    )
    save_scan(url, risk_score, verdict, history_session_id)
    pdf_available = create_pdf(report_data)

    return render_template(
        "result.html",
        validation="Valid URL",
        pdf_available=pdf_available,
        whois_info=report_data["whois"],
        dns_records=report_data["dns"],
        ssl_info=report_data["ssl"],
        **report_data,
    )


@app.get("/download-report")
def download_report():
    filename = session.get("report_filename")
    if not filename:
        return "No report is available for this session. Analyze a URL first.", 400
    path = get_report_path(filename)
    if not path.exists():
        session.pop("report_filename", None)
        return "The report could not be found. Please analyze the URL again.", 404

    response = send_file(
        path,
        as_attachment=True,
        download_name=filename,
        conditional=False,
        max_age=0,
    )
    response.headers.update({
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })
    return response


@app.get("/history")
def history():
    history_session_id = get_history_session_id()
    return render_template(
        "history.html",
        scans=get_all_scans(history_session_id),
        total_scans=get_total_scans(history_session_id),
        average_risk=get_average_risk(history_session_id),
        highest_risk=get_highest_risk(history_session_id),
        lowest_risk=get_lowest_risk(history_session_id),
    )


@app.post("/delete-scan/<int:scan_id>")
def delete_scan_route(scan_id):
    validate_csrf_token()
    delete_scan(scan_id, get_history_session_id())
    session.pop("_csrf_token", None)
    return redirect(url_for("history"))


@app.post("/clear-history")
def clear_history_route():
    validate_csrf_token()
    clear_history(get_history_session_id())
    session.pop("_csrf_token", None)
    return redirect(url_for("history"))


@app.errorhandler(413)
def request_too_large(error):
    return render_template("index.html", error="The submitted request is too large."), 413


if __name__ == "__main__":
    app.run(debug=env_flag("FLASK_DEBUG", False), use_reloader=False)
