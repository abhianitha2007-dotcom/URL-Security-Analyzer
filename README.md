# URL Security Analyzer

URL Security Analyzer is a Flask-based cybersecurity web application that analyzes URLs for phishing indicators, suspicious domain behavior, insecure configurations, and malicious reputation signals.

It combines multiple security checks into a final **Risk Score from 0–100** and provides detailed results, scan history, and downloadable PDF security reports.

## Live Demo

https://url-security-analyzer-1oky.onrender.com

> The application is hosted on Render's free tier, so the first request after inactivity may take a short time to load.

---

## Features

- HTTPS detection
- IP address detection
- Suspicious keyword detection
- URL length and subdomain analysis
- Domain age and WHOIS lookup
- DNS and SSL certificate analysis
- Typosquatting and domain similarity detection
- Homograph and punycode detection
- Redirect and webpage behavior analysis
- JavaScript and form inspection
- Security header analysis
- Cookie and CORS security checks
- Mixed-content detection
- Sensitive file exposure checks
- Technology detection
- VirusTotal threat intelligence
- Risk score calculation
- Private scan history
- PDF security reports
- SSRF protection
- CSRF protection

---

## Risk Levels

| Score | Verdict |
|---|---|
| 0–15 | Safe |
| 16–30 | Low Risk |
| 31–50 | Medium Risk |
| 51–75 | High Risk |
| 76–100 | Critical |

---

## Tech Stack

**Backend**
- Python
- Flask
- Gunicorn

**Frontend**
- HTML
- CSS
- JavaScript
- Bootstrap 5

**Database**
- SQLite

**Security & Analysis**
- Requests
- python-whois
- dnspython
- BeautifulSoup
- VirusTotal API

**Reports**
- ReportLab

**Testing**
- pytest

**Deployment**
- Render

---

## Project Structure

```text
URL-Security-Analyzer/
│
├── analyzer/
├── database/
├── templates/
├── static/
├── tests/
├── manual_tests/
├── reports/
│
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/abhianitha2007-dotcom/URL-Security-Analyzer.git
```

Move into the project:

```bash
cd URL-Security-Analyzer
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Environment Variables

Create a `.env` file in the project root:

```env
SECRET_KEY=your-secret-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
FLASK_DEBUG=true
SESSION_COOKIE_SECURE=false
```

Never upload your real `.env` file or API keys to GitHub.

---

## Run Locally

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

---

## Testing

Run the automated security and Flask test suite:

```bash
python -m pytest tests -v
```

Current automated test result:

```text
33 passed
```

---

## Security

The application includes:

- Private and local IP blocking
- Redirect SSRF protection
- Safe HTTP request handling
- CSRF protection
- Secure browser sessions
- Request-size limits
- Security response headers
- Environment-based secret management

---

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes.

The generated risk score is a security indicator and should not be treated as a guarantee that a website is completely safe or malicious.

---

## License

MIT License
