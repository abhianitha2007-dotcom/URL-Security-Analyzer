from flask import Flask, render_template, request

from analyzer.https_checker import check_https
from analyzer.url_validator import is_valid_url
from analyzer.ip_checker import contains_ip

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    url = request.form["url"]

    # Validate URL
    if not is_valid_url(url):
        return render_template(
            "result.html",
            url=url,
            validation="❌ Invalid URL",
            https_status="Not Checked",
            ip_status="Not Checked",
            risk_score="-",
            verdict="Invalid URL"
        )

    # HTTPS Check
    https = check_https(url)

    if https:
        https_result = "✅ HTTPS Detected"
    else:
        https_result = "❌ HTTP Detected"

    # IP Address Check
    ip_found = contains_ip(url)

    if ip_found:
        ip_status = "⚠️ IP Address Detected"
    else:
        ip_status = "✅ Domain Name Used"

    # Risk Score
    risk_score = 0

    if not https:
        risk_score += 40

    if ip_found:
        risk_score += 40

    # Verdict
    if risk_score == 0:
        verdict = "🟢 Safe"

    elif risk_score <= 40:
        verdict = "🟡 Suspicious"

    else:
        verdict = "🔴 High Risk"

    return render_template(
        "result.html",
        url=url,
        validation="✅ Valid URL",
        https_status=https_result,
        ip_status=ip_status,
        risk_score=risk_score,
        verdict=verdict
    )


if __name__ == "__main__":
    app.run(debug=True)