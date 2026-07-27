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
            risk_score="-",
            verdict="Invalid URL"
            
        )

    # HTTPS
    https = check_https(url)
    https_status = "✅ HTTPS Detected" if https else "❌ HTTP Detected"

    # IP
    ip_found = contains_ip(url)
    ip_status = "⚠️ IP Address Detected" if ip_found else "✅ Domain Name Used"

    # Keywords
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

    # Risk Score
    risk_score = 0

    if not https:
        risk_score += 40

    if ip_found:
        risk_score += 40

    risk_score += keyword_count * 10
    risk_score += length_score
    risk_score += subdomain_score
    risk_score += at_score
    risk_score += shortener_score
    risk_score += hyphen_score

    risk_score = min(risk_score, 100)

    # Verdict
    if risk_score <= 20:
        verdict = "🟢 Safe"
    elif risk_score <= 60:
        verdict = "🟡 Suspicious"
    else:
        verdict = "🔴 High Risk"

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
        risk_score=risk_score,
        verdict=verdict
    )


if __name__ == "__main__":
    app.run(debug=True)