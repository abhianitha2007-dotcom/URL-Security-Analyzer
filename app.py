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
from analyzer.url_validator import is_valid_url

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


# =========================================================
# ENVIRONMENT
# =========================================================

load_dotenv()


# =========================================================
# PROJECT PATHS
# =========================================================

BASE_DIR = Path(
    __file__
).resolve().parent

REPORTS_DIR = (
    BASE_DIR
    / "reports"
)

REPORTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# =========================================================
# REQUIRED CONFIGURATION
# =========================================================

SECRET_KEY = os.getenv(
    "SECRET_KEY"
)

if not SECRET_KEY:

    raise RuntimeError(
        (
            "SECRET_KEY is missing. "
            "Add SECRET_KEY to your .env file "
            "before starting the application."
        )
    )


def env_flag(
    name,
    default=False
):
    """
    Read a boolean environment variable.

    Accepted true values:
        1
        true
        yes
        on
    """

    value = os.getenv(
        name
    )

    if value is None:

        return default

    return (
        value.strip().lower()
        in {
            "1",
            "true",
            "yes",
            "on"
        }
    )


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(
    __name__
)

app.secret_key = SECRET_KEY


# =========================================================
# APPLICATION SECURITY CONFIGURATION
# =========================================================

# URL submissions are tiny. This prevents unnecessarily
# large request bodies from reaching the application.
app.config[
    "MAX_CONTENT_LENGTH"
] = 16 * 1024


# Flask's session is stored in a signed browser cookie.
app.config[
    "SESSION_COOKIE_HTTPONLY"
] = True

app.config[
    "SESSION_COOKIE_SAMESITE"
] = "Lax"

app.config[
    "SESSION_COOKIE_SECURE"
] = env_flag(
    "SESSION_COOKIE_SECURE",
    default=False
)

app.config[
    "SESSION_COOKIE_NAME"
] = "url_security_session"


# Expire long-unused browser sessions.
app.config[
    "PERMANENT_SESSION_LIFETIME"
] = timedelta(
    hours=12
)


# =========================================================
# DATABASE
# =========================================================

create_database()


# =========================================================
# SECURITY RESPONSE HEADERS
# =========================================================

@app.after_request
def add_security_headers(
    response
):
    """
    Add basic security headers to this Flask application.

    These headers protect the analyzer web interface itself.
    They are separate from the remote-site security-header
    checker used during URL analysis.
    """

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


# =========================================================
# PRIVATE HISTORY SESSION
# =========================================================

def get_history_session_id():
    """
    Return the anonymous identifier belonging to the
    current browser session.

    If the browser does not already have one,
    generate a new random identifier.
    """

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


# =========================================================
# CSRF PROTECTION
# =========================================================

def get_csrf_token():
    """
    Return a CSRF token for the current browser session.
    """

    token = session.get(
        "_csrf_token"
    )

    if not token:

        token = secrets.token_urlsafe(
            32
        )

        session[
            "_csrf_token"
        ] = token

    return token


def validate_csrf_token():
    """
    Validate a submitted CSRF token.
    """

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


# Make csrf_token() available to Jinja templates.
app.jinja_env.globals[
    "csrf_token"
] = get_csrf_token


# =========================================================
# PDF REPORT HELPERS
# =========================================================

def get_report_path(
    filename
):
    """
    Safely return the absolute path of a temporary report.
    """

    safe_filename = os.path.basename(
        filename
    )

    return (
        REPORTS_DIR
        / safe_filename
    )


def remove_previous_report():
    """
    Delete the previous PDF generated for the
    current browser session.
    """

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


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# =========================================================
# ANALYZE URL
# =========================================================

@app.route(
    "/analyze",
    methods=[
        "POST"
    ]
)
def analyze():

    # -----------------------------------------------------
    # READ USER INPUT
    # -----------------------------------------------------

    url = request.form.get(
        "url",
        ""
    ).strip()


    if not url:

        return render_template(
            "index.html",
            error=(
                "Please enter a URL."
            ),
            entered_url=url
        )


    # -----------------------------------------------------
    # NORMALIZE SCHEME
    # -----------------------------------------------------

    if not url.lower().startswith(
        (
            "http://",
            "https://"
        )
    ):

        url = (
            "https://"
            + url
        )


    # -----------------------------------------------------
    # VALIDATE PUBLIC TARGET
    #
    # url_validator.py rejects unsafe/private/local targets.
    # The safe HTTP layer also revalidates redirect hops.
    # -----------------------------------------------------

    if not is_valid_url(
        url
    ):

        return render_template(
            "index.html",
            error=(
                "Please enter a valid public HTTP or HTTPS URL."
            ),
            entered_url=url
        )


    # -----------------------------------------------------
    # PRIVATE HISTORY OWNER
    # -----------------------------------------------------

    history_session_id = (
        get_history_session_id()
    )


    # -----------------------------------------------------
    # REMOVE PREVIOUS TEMPORARY PDF
    # -----------------------------------------------------

    remove_previous_report()


    # =====================================================
    # RUN SECURITY ANALYSIS
    # =====================================================

    results = run_all_checks(
        url
    )


    # =====================================================
    # FINAL RISK ENGINE
    # =====================================================

    (
        risk_score,
        verdict,
        reasons
    ) = calculate_risk(
        results
    )


    # =====================================================
    # COMMON TEMPLATE VALUES
    # =====================================================

    https_status = (
        results["https"]["status"]
    )

    ip_status = (
        results["ip_address"]["status"]
    )

    keyword_count = (
        results["keywords"]["count"]
    )

    keywords = (
        results["keywords"]["matches"]
    )

    url_length = (
        results["url_length"]["length"]
    )

    length_category = (
        results["url_length"]["status"]
    )

    subdomain_count = (
        results["subdomains"]["count"]
    )

    subdomain_status = (
        results["subdomains"]["status"]
    )

    at_status = (
        results["at_symbol"]["status"]
    )

    shortener_status = (
        results["shortener"]["status"]
    )

    hyphen_count = (
        results["hyphens"]["count"]
    )

    hyphen_status = (
        results["hyphens"]["status"]
    )

    domain_age = (
        results["domain_age"]
    )

    whois_info = (
        results["whois"]
    )

    dns_records = (
        results["dns"]
    )

    ssl_info = (
        results["ssl"]
    )

    tld = (
        results["tld"]["value"]
    )

    tld_status = (
        results["tld"]["status"]
    )


    # =====================================================
    # SAVE PRIVATE SCAN HISTORY
    # =====================================================

    save_scan(
        url,
        risk_score,
        verdict,
        history_session_id
    )


    # =====================================================
    # PDF REPORT DATA
    # =====================================================

    report_data = {

        "url": url,

        "risk_score": risk_score,

        "verdict": verdict,

        "reasons": reasons,

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


    # =====================================================
    # GENERATE UNIQUE TEMPORARY PDF
    # =====================================================

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
            str(
                pdf_path
            )
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


    # =====================================================
    # RESULT PAGE
    # =====================================================

    return render_template(

        "result.html",

        url=url,

        validation=(
            "✅ Valid URL"
        ),

        risk_score=risk_score,

        verdict=verdict,

        reasons=reasons,

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


# =========================================================
# DOWNLOAD REPORT
# =========================================================

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


    return send_file(
        report_path,
        as_attachment=True,
        download_name=(
            "security_report.pdf"
        )
    )


# =========================================================
# PRIVATE HISTORY PAGE
# =========================================================

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


# =========================================================
# DELETE ONE PRIVATE SCAN
# =========================================================

@app.route(
    "/delete-scan/<int:scan_id>",
    methods=[
        "POST"
    ]
)
def delete_scan_route(
    scan_id
):

    validate_csrf_token()


    history_session_id = (
        get_history_session_id()
    )


    delete_scan(
        scan_id,
        history_session_id
    )


    # Rotate token after destructive action.
    session.pop(
        "_csrf_token",
        None
    )


    return redirect(
        url_for(
            "history"
        )
    )


# =========================================================
# CLEAR PRIVATE HISTORY
# =========================================================

@app.route(
    "/clear-history",
    methods=[
        "POST"
    ]
)
def clear_history_route():

    validate_csrf_token()


    history_session_id = (
        get_history_session_id()
    )


    clear_history(
        history_session_id
    )


    # Rotate token after destructive action.
    session.pop(
        "_csrf_token",
        None
    )


    return redirect(
        url_for(
            "history"
        )
    )


# =========================================================
# ERROR HANDLER
# =========================================================

@app.errorhandler(
    413
)
def request_too_large(
    error
):

    return render_template(
        "index.html",
        error=(
            "The submitted request is too large."
        )
    ), 413


# =========================================================
# DEVELOPMENT SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=env_flag(
            "FLASK_DEBUG",
            default=False
        ),
        use_reloader=False
    )