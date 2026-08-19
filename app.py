from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import os
import secrets

from dotenv import load_dotenv

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for
)

from analyzer.detection_manager import run_all_checks
from analyzer.pdf_generator import generate_pdf
from analyzer.risk_engine import calculate_risk
from analyzer.url_validator import (
    get_last_validation_result,
    validate_url_input
)

from database.database import (
    clear_history,
    create_database,
    delete_scan,
    get_all_scans,
    get_average_risk,
    get_highest_risk,
    get_lowest_risk,
    get_total_scans,
    save_scan
)


load_dotenv()


BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"

REPORTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    os.environ["SECRET_KEY"] = SECRET_KEY


def env_flag(name, default=False):
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on"
    }


app = Flask(__name__)

app.secret_key = SECRET_KEY

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = env_flag(
    "SESSION_COOKIE_SECURE",
    default=False
)

app.config["SESSION_COOKIE_NAME"] = (
    "url_security_session"
)

app.config["PERMANENT_SESSION_LIFETIME"] = (
    timedelta(hours=12)
)


create_database()


# Kept as an app-level name for route/test compatibility.
# Outbound requests still use the stricter network validator
# inside safe_http.py.
is_valid_url = validate_url_input


@app.after_request
def add_security_headers(response):
    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"

    response.headers[
        "Permissions-Policy"
    ] = (
        "camera=(), microphone=(), geolocation=()"
    )

    return response


def get_history_session_id():
    session.permanent = True

    history_session_id = session.get(
        "history_session_id"
    )

    if not history_session_id:
        history_session_id = uuid4().hex

        session[
            "history_session_id"
        ] = history_session_id

    return history_session_id


def get_csrf_token():
    token = session.get(
        "_csrf_token"
    )

    if not token:
        token = secrets.token_urlsafe(32)

        session[
            "_csrf_token"
        ] = token

    return token


def validate_csrf_token():
    submitted_token = request.form.get(
        "csrf_token",
        ""
    )

    expected_token = session.get(
        "_csrf_token",
        ""
    )

    if (
        not submitted_token
        or not expected_token
        or not secrets.compare_digest(
            submitted_token,
            expected_token
        )
    ):
        abort(
            400,
            description=(
                "Invalid or missing CSRF token."
            )
        )


app.jinja_env.globals[
    "csrf_token"
] = get_csrf_token


def get_report_path(filename):
    safe_filename = os.path.basename(
        filename
    )

    return REPORTS_DIR / safe_filename


def remove_previous_report():
    previous_filename = session.pop(
        "report_filename",
        None
    )

    if not previous_filename:
        return

    previous_path = get_report_path(
        previous_filename
    )

    if previous_path.exists():
        try:
            previous_path.unlink()
        except OSError:
            pass


def default_scan_status():
    return {
        "mode": "full",
        "label": "Full Analysis",
        "complete": True,
        "network_available": True,
        "code": "public_target",
        "message": (
            "URL, domain, network, webpage and "
            "threat-intelligence checks were performed."
        )
    }


def default_content_warning():
    return {
        "show": False,
        "type": None,
        "icon": None,
        "title": None,
        "message": None
    }


@app.route("/")
def home():
    return render_template(
        "index.html"
    )


@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():
    url = request.form.get(
        "url",
        ""
    ).strip()

    if not url:
        return render_template(
            "index.html",
            error="Please enter a URL.",
            entered_url=url
        )

    if not url.lower().startswith(
        (
            "http://",
            "https://"
        )
    ):
        url = "https://" + url

    if not is_valid_url(url):
        validation_result = (
            get_last_validation_result()
        )

        return render_template(
            "index.html",
            error=validation_result.get(
                "message",
                (
                    "Please enter a valid public "
                    "HTTP or HTTPS URL."
                )
            ),
            entered_url=url
        )

    history_session_id = (
        get_history_session_id()
    )

    remove_previous_report()

    results = run_all_checks(
        url
    )

    (
        risk_score,
        verdict,
        reasons
    ) = calculate_risk(
        results
    )

    scan_status = results.get(
        "scan_status",
        default_scan_status()
    )

    network_status = results.get(
        "network_status",
        {}
    )

    content_warning = results.get(
        "content_warning",
        default_content_warning()
    )

    https_status = results[
        "https"
    ][
        "status"
    ]

    ip_status = results[
        "ip_address"
    ][
        "status"
    ]

    keyword_count = results[
        "keywords"
    ][
        "count"
    ]

    keywords = results[
        "keywords"
    ][
        "matches"
    ]

    url_length = results[
        "url_length"
    ][
        "length"
    ]

    length_category = results[
        "url_length"
    ][
        "status"
    ]

    subdomain_count = results[
        "subdomains"
    ][
        "count"
    ]

    subdomain_status = results[
        "subdomains"
    ][
        "status"
    ]

    at_status = results[
        "at_symbol"
    ][
        "status"
    ]

    shortener_status = results[
        "shortener"
    ][
        "status"
    ]

    hyphen_count = results[
        "hyphens"
    ][
        "count"
    ]

    hyphen_status = results[
        "hyphens"
    ][
        "status"
    ]

    domain_age = results[
        "domain_age"
    ]

    whois_info = results[
        "whois"
    ]

    dns_records = results[
        "dns"
    ]

    ssl_info = results[
        "ssl"
    ]

    tld = results[
        "tld"
    ][
        "value"
    ]

    tld_status = results[
        "tld"
    ][
        "status"
    ]

    save_scan(
        url,
        risk_score,
        verdict,
        history_session_id
    )

    report_data = {
        "url": url,
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons,
        "scan_status": scan_status,
        "network_status": network_status,
        "content_warning": content_warning,
        "https_status": https_status,
        "ip_status": ip_status,
        "keyword_count": keyword_count,
        "keywords": keywords,
        "url_length": url_length,
        "length_category": length_category,
        "subdomain_count": subdomain_count,
        "subdomain_status": subdomain_status,
        "at_status": at_status,
        "shortener_status": shortener_status,
        "hyphen_count": hyphen_count,
        "hyphen_status": hyphen_status,
        "domain_age": domain_age,
        "tld": tld,
        "tld_status": tld_status,
        "whois": whois_info,
        "dns": dns_records,
        "ssl": ssl_info,
        "analysis_results": results
    }

    report_filename = (
        "security_report_"
        + uuid4().hex
        + ".pdf"
    )

    pdf_path = get_report_path(
        report_filename
    )

    pdf_available = False

    try:
        generate_pdf(
            report_data,
            str(pdf_path)
        )

        session[
            "report_filename"
        ] = report_filename

        pdf_available = True

    except Exception as error:
        app.logger.exception(
            "PDF report generation failed: %s",
            error
        )

        session.pop(
            "report_filename",
            None
        )

    return render_template(
        "result.html",
        url=url,
        validation="✅ Valid URL",
        risk_score=risk_score,
        verdict=verdict,
        reasons=reasons,
        scan_status=scan_status,
        network_status=network_status,
        content_warning=content_warning,
        https_status=https_status,
        ip_status=ip_status,
        keyword_count=keyword_count,
        keywords=keywords,
        url_length=url_length,
        length_category=length_category,
        subdomain_count=subdomain_count,
        subdomain_status=subdomain_status,
        at_status=at_status,
        shortener_status=shortener_status,
        hyphen_count=hyphen_count,
        hyphen_status=hyphen_status,
        domain_age=domain_age,
        whois_info=whois_info,
        dns_records=dns_records,
        ssl_info=ssl_info,
        tld=tld,
        tld_status=tld_status,
        analysis_results=results,
        pdf_available=pdf_available
    )


@app.route(
    "/download-report"
)
def download_report():
    report_filename = session.get(
        "report_filename"
    )

    if not report_filename:
        return (
            (
                "No report is available for this session. "
                "Analyze a URL first."
            ),
            400
        )

    report_path = get_report_path(
        report_filename
    )

    if not report_path.exists():
        session.pop(
            "report_filename",
            None
        )

        return (
            (
                "The report could not be found. "
                "Please analyze the URL again."
            ),
            404
        )

    response = send_file(
        report_path,
        as_attachment=True,
        download_name=report_filename,
        conditional=False,
        max_age=0
    )

    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, "
        "max-age=0"
    )

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response


@app.route(
    "/history"
)
def history():
    history_session_id = (
        get_history_session_id()
    )

    scans = get_all_scans(
        history_session_id
    )

    total_scans = get_total_scans(
        history_session_id
    )

    average_risk = get_average_risk(
        history_session_id
    )

    highest_risk = get_highest_risk(
        history_session_id
    )

    lowest_risk = get_lowest_risk(
        history_session_id
    )

    return render_template(
        "history.html",
        scans=scans,
        total_scans=total_scans,
        average_risk=average_risk,
        highest_risk=highest_risk,
        lowest_risk=lowest_risk
    )


@app.route(
    "/delete-scan/<int:scan_id>",
    methods=["POST"]
)
def delete_scan_route(scan_id):
    validate_csrf_token()

    history_session_id = (
        get_history_session_id()
    )

    delete_scan(
        scan_id,
        history_session_id
    )

    session.pop(
        "_csrf_token",
        None
    )

    return redirect(
        url_for("history")
    )


@app.route(
    "/clear-history",
    methods=["POST"]
)
def clear_history_route():
    validate_csrf_token()

    history_session_id = (
        get_history_session_id()
    )

    clear_history(
        history_session_id
    )

    session.pop(
        "_csrf_token",
        None
    )

    return redirect(
        url_for("history")
    )


@app.errorhandler(413)
def request_too_large(error):
    return render_template(
        "index.html",
        error=(
            "The submitted request is too large."
        )
    ), 413


if __name__ == "__main__":
    app.run(
        debug=env_flag(
            "FLASK_DEBUG",
            default=False
        ),
        use_reloader=False
    )