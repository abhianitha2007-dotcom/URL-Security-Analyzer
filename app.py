from flask import Flask
from flask import render_template
from flask import request

app = Flask(__name__)


@app.route("/")
def home():

    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    url = request.form["url"]

    return f"""

    <h2>URL Received</h2>

    <p>{url}</p>

    """


if __name__ == "__main__":

    app.run(debug=True)