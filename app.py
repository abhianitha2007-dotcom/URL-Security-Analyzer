from flask import (
    Flask,
    redirect,
    render_template,
    request,
    send_file,
    session
)

import os

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


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "url-security-analyzer-secret-key"
)

create_database()


@app.route("/")
def home():
    return render_template(
        "index.html"
    )


@app.route("/analyze", methods=["POST"])
def analyze():

    url = request.form.get(
        "url",
        ""
    ).strip()

    if not url:
        return render_template(
            "index.html",
            error="Please enter a URL."
        )

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "https://" + url

    if not is_valid_url(url):
        return render_template(
            "index.html",
            error="Please enter a valid URL."
        )

    # ==========================================
    # RUN ALL SECURITY CHECKS
    # ==========================================

    results = run_all_checks(url)

    risk_score, verdict, reasons = calculate_risk(
        results
    )

    # ==========================================
    # EXTRACT VALUES FOR THE TEMPLATE
    # ==========================================

    https_status = results["https"]["status"]
    ip_status = results["ip_address"]["status"]

    keyword_count = results["keywords"]["count"]
    keywords = results["keywords"]["matches"]

    url_length = results["url_length"]["length"]
    length_category = results["url_length"]["status"]

    subdomain_count = results["subdomains"]["count"]
    subdomain_status = results["subdomains"]["status"]

    at_status = results["at_symbol"]["status"]
    shortener_status = results["shortener"]["status"]

    hyphen_count = results["hyphens"]["count"]
    hyphen_status = results["hyphens"]["status"]

    domain_age = results["domain_age"]
    whois_info = results["whois"]
    dns_records = results["dns"]
    ssl_info = results["ssl"]

    tld = results["tld"]["value"]
    tld_status = results["tld"]["status"]

    # ==========================================
    # REPORT DATA
    # ==========================================

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
        "ssl": ssl_info
    }

    # Store only the compact report in the session.
    session["report_data"] = report_data

    # ==========================================
    # SAVE SCAN HISTORY
    # ==========================================

    save_scan(
        url,
        risk_score,
        verdict
    )

    # ==========================================
    # GENERATE PDF
    # ==========================================

    reports_dir = "reports"

    os.makedirs(
        reports_dir,
        exist_ok=True
    )

    pdf_path = os.path.join(
        reports_dir,
        "security_report.pdf"
    )

    pdf_report_data = {
        **report_data,
        "analysis_results": results
    }

    generate_pdf(
        pdf_report_data,
        pdf_path
    )

    # ==========================================
    # DISPLAY RESULT PAGE
    # ==========================================

    return render_template(
        "result.html",

        url=url,
        validation="✅ Valid URL",

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

        analysis_results=results
    )


@app.route("/download-report")
def download_report():

    output_path = os.path.join(
        "reports",
        "security_report.pdf"
    )

    if not os.path.exists(output_path):

        return (
            "No report available. Analyze a URL first.",
            400
        )

    return send_file(
        output_path,
        as_attachment=True,
        download_name="security_report.pdf"
    )
@app.route("/history")
def history():

    scans = get_all_scans()

    return render_template(
        "history.html",

        scans=scans,

        total_scans=get_total_scans(),
        average_risk=get_average_risk(),
        highest_risk=get_highest_risk(),
        lowest_risk=get_lowest_risk()
    )


@app.route("/delete-scan/<int:scan_id>")
def delete_scan_route(scan_id):

    delete_scan(
        scan_id
    )

    return redirect(
        "/history"
    )


@app.route("/clear-history")
def clear_history_route():

    clear_history()

    return redirect(
        "/history"
    )


if __name__ == "__main__":

    app.run(
        debug=True,
        use_reloader=False
    )