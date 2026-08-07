# URL Security Analyzer

URL Security Analyzer is a Flask-based cybersecurity web application that analyzes URLs for phishing indicators, suspicious domain behavior, insecure configurations, and malicious reputation signals.

It combines multiple security checks into a final **Risk Score from 0–100** and provides detailed results, scan history, and downloadable PDF reports.

---

## Features

- HTTPS detection
- IP address detection
- Suspicious keyword detection
- URL length analysis
- Subdomain analysis
- URL shortener detection
- Domain age analysis
- WHOIS lookup
- DNS analysis
- SSL certificate inspection
- Typosquatting and domain similarity detection
- Redirect analysis
- JavaScript and form inspection
- Security header analysis
- Cookie security checks
- CORS analysis
- Mixed-content detection
- Sensitive file exposure checks
- Technology detection
- VirusTotal threat intelligence
- Risk score calculation
- SQLite scan history
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

**Frontend**
- HTML
- CSS
- JavaScript
- Bootstrap 5

**Database**
- SQLite

**Security / Analysis**
- Requests
- python-whois
- dnspython
- BeautifulSoup
- VirusTotal API

**Reports**
- ReportLab

**Testing**
- pytest

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
├── .gitignore
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone <repository-url>
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

Do not upload your real `.env` file to GitHub.

---

## Run the Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## Testing

Run the automated test suite:

```bash
python -m pytest tests -v
```

Current result:

```text
33 passed
```

---

## Security

The application includes:

- Private/local IP blocking
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

The generated risk score should be treated as a security indicator, not a guarantee that a website is completely safe or malicious.

---

## License

MIT License