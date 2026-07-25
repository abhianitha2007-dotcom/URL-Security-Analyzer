from flask import Flask, render_template, request

from analyzer.https_checker import check_https
from analyzer.url_validator import is_valid_url
from analyzer.ip_checker import contains_ip
from analyzer.keyword_checker import check_keywords

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    url = request.form["url"]

    if not is_valid_url(url):
        return render_template(
            "result.html",
            url=url,
            validation="❌ Invalid URL",
            https_status="Not Checked",
            ip_status="Not Checked",
            keyword_count=0,
            keywords=[],
            risk_score="-",
            verdict="Invalid URL"
        )

    https = check_https(url)
    https_result = "✅ HTTPS Detected" if https else "❌ HTTP Detected"

    ip_found = contains_ip(url)
    ip_status = (
        "⚠️ IP Address Detected"
        if ip_found
        else "✅ Domain Name Used"
    )

    keyword_count, keywords = check_keywords(url)

    risk_score = 0

    if not https:
        risk_score += 40

    if ip_found:
        risk_score += 40

    risk_score += keyword_count * 10

    risk_score = min(risk_score, 100)

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
        https_status=https_result,
        ip_status=ip_status,
        keyword_count=keyword_count,
        keywords=keywords,
        risk_score=risk_score,
        verdict=verdict
    )


if __name__ == "__main__":
    app.run(debug=True)