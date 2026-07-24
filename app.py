from flask import Flask, render_template, request

from analyzer.https_checker import check_https
from analyzer.url_validator import is_valid_url

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
            https_status="Not Checked"
        )

    https = check_https(url)

    if https:
        https_result = "✅ HTTPS Detected"
    else:
        https_result = "❌ HTTP Detected"

    return render_template(
        "result.html",
        url=url,
        validation="✅ Valid URL",
        https_status=https_result
    )


if __name__ == "__main__":
    app.run(debug=True)