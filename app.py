from flask import Flask, render_template, request

from analyzer.https_checker import check_https
from analyzer.url_validator import is_valid_url
from analyzer.ip_checker import contains_ip
from analyzer.keyword_checker import check_keywords
from analyzer.length_checker import check_url_length
from analyzer.subdomain_checker import count_subdomains
from analyzer.at_symbol_checker import check_at_symbol
from analyzer.shortener_checker import check_shortener
from analyzer.hyphen_checker import check_hyphen
from analyzer.domain_age_checker import check_domain_age
from analyzer.risk_engine import calculate_risk
from analyzer.whois_checker import get_whois_info
from analyzer.dns_checker import get_dns_records

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    url = request.form["url"].strip()

    # Automatically add HTTPS if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Validate URL
    if not is_valid_url(url):
        return render_template(
            "result.html",
            url=url,
            validation="❌ Invalid URL",
            https_status="Not Checked",
            ip_status="Not Checked",
            keyword_count=0,
            keywords=[],
            url_length="-",
            length_category="Not Checked",
            subdomain_count="-",
            subdomain_status="Not Checked",
            at_status="Not Checked",
            shortener_status="Not Checked",
            hyphen_count="-",
            hyphen_status="Not Checked",
            domain_age="Unknown",
            domain_age_status="Not Checked",
            risk_score="-",
            verdict="Invalid URL"
        )

    # HTTPS
    https = check_https(url)
    https_status = "✅ HTTPS Detected" if https else "❌ HTTP Detected"

    # IP Address
    ip_found = contains_ip(url)
    ip_status = "⚠️ IP Address Detected" if ip_found else "✅ Domain Name Used"

    # Suspicious Keywords
    keyword_count, keywords = check_keywords(url)

    # URL Length
    url_length, length_category, length_score = check_url_length(url)

    # Subdomains
    subdomain_count, subdomain_status, subdomain_score = count_subdomains(url)

    # @ Symbol
    at_found, at_status, at_score = check_at_symbol(url)

    # URL Shortener
    shortener_found, shortener_status, shortener_score = check_shortener(url)

    # Hyphen Detection
    hyphen_count, hyphen_status, hyphen_score = check_hyphen(url)

    # Domain Age
    domain_age = check_domain_age(url)
    whois_info = get_whois_info(url)
    dns_records = get_dns_records(url)
    domain_age_status = domain_age["message"]
    domain_age_score = 20 if domain_age["risk"] else 0

    # Calculate Risk
    risk_score, verdict = calculate_risk(
        https,
        ip_found,
        keyword_count,
        length_score,
        subdomain_score,
        at_score,
        shortener_score,
        hyphen_score,
        domain_age_score
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
        domain_age=domain_age["age"],
        domain_age_status=domain_age_status,
        whois_info=whois_info,
        dns_records=dns_records,
        risk_score=risk_score,
        verdict=verdict
    )


if __name__ == "__main__":
    app.run(debug=True)