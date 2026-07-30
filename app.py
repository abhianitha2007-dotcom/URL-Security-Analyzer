from flask import (
    Flask,
    render_template,
    request,
    send_file,
    session,
    redirect
)

import os

from database.database import (
    create_database,
    save_scan,
    get_all_scans,
    get_scan_by_id,
    delete_scan,
    clear_history,
    get_total_scans,
    get_average_risk,
    get_highest_risk,
    get_lowest_risk
)

from analyzer.url_validator import is_valid_url
from analyzer.https_checker import check_https
from analyzer.ip_checker import contains_ip
from analyzer.keyword_checker import check_keywords
from analyzer.length_checker import check_url_length
from analyzer.subdomain_checker import count_subdomains
from analyzer.at_symbol_checker import check_at_symbol
from analyzer.shortener_checker import check_shortener
from analyzer.hyphen_checker import check_hyphen
from analyzer.domain_age_checker import check_domain_age
from analyzer.whois_checker import get_whois_info
from analyzer.dns_checker import get_dns_records
from analyzer.ssl_checker import get_ssl_info
from analyzer.tld_checker import check_tld
from analyzer.risk_engine import calculate_risk
from analyzer.pdf_generator import generate_pdf


app = Flask(__name__)


# Secret key for session storage
app.secret_key = "url-security-analyzer-secret-key"


# Create database automatically
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
            "result.html",
            validation="❌ No URL entered"
        )


    # Add HTTPS automatically
    if not url.startswith(
        ("http://", "https://")
    ):

        url = "https://" + url



    # ----------------------------
    # URL Validation
    # ----------------------------

    if not is_valid_url(url):

        return render_template(
            "result.html",

            url=url,

            validation="❌ Invalid URL",

            risk_score="-",

            verdict="Invalid URL"

        )



    # ----------------------------
    # Security Checks
    # ----------------------------


    https = check_https(url)


    https_status = (
        "✅ HTTPS Detected"
        if https
        else
        "❌ HTTP Detected"
    )



    ip_found = contains_ip(url)


    ip_status = (
        "⚠️ IP Address Detected"
        if ip_found
        else
        "✅ Domain Name Used"
    )



    keyword_count, keywords = check_keywords(url)



    url_length, length_category, length_score = (
        check_url_length(url)
    )



    subdomain_count, subdomain_status, subdomain_score = (
        count_subdomains(url)
    )



    at_found, at_status, at_score = (
        check_at_symbol(url)
    )



    shortener_found, shortener_status, shortener_score = (
        check_shortener(url)
    )



    hyphen_count, hyphen_status, hyphen_score = (
        check_hyphen(url)
    )



    domain_age = check_domain_age(url)


    domain_age_score = (
        20
        if domain_age.get("risk")
        else 0
    )



    whois_info = get_whois_info(url)



    dns_records = get_dns_records(url)



    ssl_info = get_ssl_info(url)



    tld, tld_status, tld_score = (
        check_tld(url)
    )



    # ----------------------------
    # Risk Calculation
    # ----------------------------


    risk_score, verdict = calculate_risk(

        https,

        ip_found,

        keyword_count,

        length_score,

        subdomain_score,

        at_score,

        shortener_score,

        hyphen_score,

        domain_age_score,

        tld_score

    )



    # ----------------------------
    # Report Data
    # ----------------------------


    report_data = {


        "url": url,

        "risk_score": risk_score,

        "verdict": verdict,


        "https_status": https_status,

        "ip_status": ip_status,


        "keyword_count": keyword_count,


        "url_length": url_length,


        "subdomain_count": subdomain_count,


        "at_status": at_status,


        "shortener_status": shortener_status,


        "hyphen_count": hyphen_count,


        "domain_age": domain_age,


        "tld_status": tld_status,


        "whois": whois_info,


        "dns": dns_records,


        "ssl": ssl_info

    }



    # Store report for download

    session["report_data"] = report_data



    # Save history

    save_scan(

        url,

        risk_score,

        verdict

    )



    # Generate PDF

    reports_dir = "reports"


    os.makedirs(
        reports_dir,
        exist_ok=True
    )



    pdf_path = os.path.join(
        reports_dir,
        "security_report.pdf"
    )



    generate_pdf(
        report_data,
        pdf_path
    )



    return render_template(

        "result.html",


        url=url,


        validation="✅ Valid URL",


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


        risk_score=risk_score,


        verdict=verdict

    )




@app.route("/download-report")
def download_report():


    report_data = session.get(
        "report_data"
    )


    if not report_data:

        return (
            "No report available. Analyze a URL first.",
            400
        )



    reports_dir = "reports"


    os.makedirs(
        reports_dir,
        exist_ok=True
    )


    output_path = os.path.join(

        reports_dir,

        "security_report.pdf"

    )



    generate_pdf(

        report_data,

        output_path

    )



    return send_file(

        output_path,

        as_attachment=True,

        download_name="security_report.pdf"

    )




@app.route("/history")
def history():

    scans = get_all_scans()

    total_scans = get_total_scans()

    average_risk = get_average_risk()

    highest_risk = get_highest_risk()

    lowest_risk = get_lowest_risk()

    return render_template(

        "history.html",

        scans=scans,

        total_scans=total_scans,

        average_risk=average_risk,

        highest_risk=highest_risk,

        lowest_risk=lowest_risk

    )

@app.route("/delete-scan/<int:scan_id>")
def delete_scan_route(scan_id):

    delete_scan(scan_id)

    return redirect("/history")

@app.route("/clear-history")
def clear_history_route():

    clear_history()

    return redirect("/history")

if __name__ == "__main__":

    app.run(
        debug=True,
        use_reloader=False
    )