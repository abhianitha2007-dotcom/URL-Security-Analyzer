from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "<h1>Home Page</h1>"

@app.route("/about")
def about():
    return "<h2>About the Project</h2>"

@app.route("/contact")
def contact():
    return "<h2>Contact Page</h2>"

if __name__ == "__main__":
    app.run(debug=True)