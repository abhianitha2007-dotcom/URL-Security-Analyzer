# 🔐 URL Security Analyzer

A web-based cybersecurity application that analyzes URLs for phishing indicators and calculates a security risk score.

The project identifies suspicious characteristics commonly used in phishing attacks and provides a detailed security report.

---

# 🚀 Features

## URL Analysis

✅ HTTPS Detection  
✅ IP Address Detection  
✅ Suspicious Keyword Detection  
✅ URL Length Analysis  
✅ Subdomain Detection  
✅ @ Symbol Detection  
✅ URL Shortener Detection  
✅ Hyphen Analysis  
✅ TLD Reputation Checking  

---

## Domain Intelligence

✅ WHOIS Information  
✅ Domain Age Analysis  
✅ DNS Record Lookup  
✅ SSL Certificate Analysis  

---

## Risk Assessment

✅ Multi-factor Risk Engine  
✅ Security Score (0-100)  
✅ Safe / Suspicious / High Risk Classification  

---

## Reports & History

✅ PDF Security Report Generation  
✅ SQLite Scan History  
✅ Previous Scan Tracking  

---

# 🛠 Tech Stack

## Backend

- Python
- Flask

## Frontend

- HTML
- CSS

## Database

- SQLite

## Security Libraries

- python-whois
- dnspython
- SSL module

## Version Control

- Git
- GitHub

---

# 📂 Project Structure

```
URL-Security-Analyzer/

│
├── analyzer/
│   ├── https_checker.py
│   ├── ip_checker.py
│   ├── keyword_checker.py
│   ├── length_checker.py
│   ├── subdomain_checker.py
│   ├── at_symbol_checker.py
│   ├── shortener_checker.py
│   ├── hyphen_checker.py
│   ├── domain_age_checker.py
│   ├── whois_checker.py
│   ├── dns_checker.py
│   ├── ssl_checker.py
│   ├── tld_checker.py
│   ├── risk_engine.py
│   └── pdf_generator.py
│
├── database/
│   ├── database.py
│   └── scans.db
│
├── templates/
│   ├── index.html
│   ├── result.html
│   └── history.html
│
├── static/
│   └── style.css
│
├── reports/
│
├── app.py
├── requirements.txt
├── README.md
└── .gitignore

```

---

# ▶️ Installation

Clone the repository:

```bash
git clone <repository-url>
```

Move into project directory:

```bash
cd URL-Security-Analyzer
```

Create virtual environment:

```bash
python -m venv venv
```

Activate environment:

Windows:

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run application:

```bash
python app.py
```

Open browser:

```
http://127.0.0.1:5000
```

---

# 🔍 How It Works

1. User enters a URL.
2. Analyzer performs multiple security checks.
3. Each indicator contributes to the risk score.
4. Final score determines security level.
5. User can download a PDF report.
6. Scan history is stored in SQLite.

---

# 🔮 Future Improvements

- SMS phishing detection
- QR code URL scanning
- Machine learning based phishing prediction
- Browser extension
- REST API
- User authentication

---

# 📜 License

MIT License