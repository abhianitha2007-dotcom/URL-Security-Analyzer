# URL Security Analyzer

URL Security Analyzer is a Flask-based cybersecurity web application that analyzes URLs for phishing indicators, suspicious domain behavior, insecure configurations, and malicious reputation signals.

It combines multiple security checks into a final **Risk Score from 0–100** and provides detailed analysis results, private scan history, and downloadable PDF security reports.

## Live Demo

https://url-security-analyzer-1oky.onrender.com

> The application is hosted on Render's free tier, so the first request after inactivity may take a short time to load.

---

## Features

- HTTPS detection
- IP address detection
- Suspicious keyword detection
- URL length analysis
- Subdomain analysis
- Hyphen and `@` symbol detection
- URL shortener detection
- Query parameter analysis
- Suspicious file extension detection
- Domain age analysis
- WHOIS lookup
- DNS record analysis
- SSL certificate inspection
- TLD risk analysis
- URL entropy analysis
- Typosquatting detection
- Domain similarity detection
- Punycode detection
- Unicode homograph detection
- Redirect analysis
- JavaScript behavior inspection
- Form analysis
- Page content analysis
- Security header analysis
- Response header analysis
- Cookie security checks
- CORS security checks
- Mixed-content detection
- robots.txt analysis
- Sitemap analysis
- Sensitive file exposure detection
- HTTP method analysis
- Technology detection
- VirusTotal threat intelligence
- Risk score calculation
- Private browser-based scan history
- Downloadable PDF security reports
- SSRF protection
- CSRF protection
- Detailed URL validation errors

---

## Risk Levels

| Score | Verdict |
|---|---|
| 0–15 | Safe |
| 16–30 | Low Risk |
| 31–50 | Medium Risk |
| 51–75 | High Risk |
| 76–100 | Critical |

The final score is calculated from multiple categories of evidence instead of relying on a single indicator.

---

## Tech Stack

### Backend

- Python
- Flask
- Gunicorn

### Frontend

- HTML
- CSS
- JavaScript
- Bootstrap 5

### Database

- SQLite

### Security & Analysis

- Requests
- python-whois
- dnspython
- BeautifulSoup
- VirusTotal API

### Reports

- ReportLab

### Testing

- pytest

### Deployment

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

For production deployment:

```env
FLASK_DEBUG=false
SESSION_COOKIE_SECURE=true
```

---

## Run Locally

Start the application:

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

---

## Testing

Run the automated test suite:

```bash
python -m pytest tests -v
```

Current automated test result:

```text
42 passed
```

The automated tests cover areas including:

- Flask routes
- SSRF protection
- Private and local address blocking
- Safe redirect handling
- CSRF protection
- Scan history isolation
- PDF report routes
- Request-size limits
- URL validation
- DNS failure handling
- Embedded credential blocking
- Validation error messages

---

## Security

The application includes multiple protections for safely analyzing user-supplied URLs:

- Private and local IP blocking
- DNS-based public target validation
- Redirect SSRF protection
- Safe HTTP request handling
- Bounded network timeouts
- Environment proxy isolation
- CSRF protection
- Secure browser sessions
- Request-size limits
- Security response headers
- Environment-based secret management

Network requests are validated before being sent to reduce the risk of Server-Side Request Forgery attacks.

---

## Performance

The analyzer uses:

- HTTP connection reuse
- Shared WHOIS lookup caching
- Concurrent network analysis
- Parallel sitemap processing
- Bounded worker pools

These optimizations reduce scan time while keeping the security checks and scoring system intact.

---

## Validation

The application distinguishes between different URL validation failures, including:

- Invalid URL format
- Unsupported URL scheme
- Private or local network targets
- Invalid ports
- Embedded usernames or passwords
- DNS resolution failures

A valid but unavailable domain is reported separately from an incorrectly formatted URL.

---

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes.

The generated risk score is a security indicator and should not be treated as a guarantee that a website is completely safe or malicious.

External threat-intelligence results may change over time as security vendors update their classifications.

---

## License

MIT License