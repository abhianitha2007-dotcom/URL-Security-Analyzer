# URL Security Analyzer

URL Security Analyzer is a defensive Flask application that produces three independent outcomes for a public URL:

- **Threat Risk (0–100):** corroborated phishing, malware, deceptive structure, behavior, and reputation evidence.
- **Security Posture (0–100):** TLS, response headers, cookies, CORS, mixed content, and server-hardening observations.
- **Content Warning:** adult/18+, gambling, or financial context. A content label does not by itself mean a site is malicious.

The analyzer either returns a complete assessment or returns no score, history entry, or PDF. There is no partial-analysis result.

## What changed in engine 4

- Every page-level module consumes one captured response, eliminating conflicting results from repeated page downloads during a scan.
- A versioned URL-language model replaces the fixed suspicious-keyword and brand lists.
- Normal terms such as `login`, `account`, or `payment` do not add points on their own.
- TLDs and ordinary query-parameter names are reported factually, not treated as reputation evidence.
- A single isolated VirusTotal classification is recorded as inconclusive and does not change the score.
- Missing headers, cookie settings, and CORS findings affect Security Posture rather than malicious-threat risk.
- Required-module failures raise a complete-analysis error instead of silently becoming zero points.
- Engine, policy, content-policy, model, and page-snapshot versions are shown in each result.

No automated classifier can be perfectly accurate. The scoring policy reduces false positives by requiring corroboration, preserving evidence provenance, and keeping non-threat observations out of the threat score.

## Scoring bands

| Score | Verdict |
|---:|---|
| 0 | Safe |
| 1–24 | Low Risk |
| 25–49 | Medium Risk |
| 51–75 | High Risk |
| 76–100 | Critical |

`Safe` means no corroborated malicious evidence was observed during this completed scan; it is not a guarantee.

The versioned policy lives in [`analyzer/data/scoring_policy.json`](analyzer/data/scoring_policy.json). Runtime code never adds every checker score together. It groups threat evidence into lexical, structural, domain, behavior, and reputation categories, applies category caps, and adds only documented corroboration bonuses.

## Data-driven URL language model

The packaged model is generated from:

- verified phishing URLs from [PhishTank](https://www.phishtank.net/developer_info.php), and
- high-ranking benign domains from [Tranco](https://tranco-list.eu/).

Dataset files are intentionally not committed. The model stores source hashes, sample counts, model version, and holdout metrics. Rebuild it with:

```bash
python scripts/train_url_language_model.py \
  --phishtank /path/to/verified_online.csv \
  --tranco /path/to/tranco-list.zip \
  --tranco-id YOUR_LIST_ID \
  --output analyzer/data/url_language_model.json.gz
```

Training uses a fixed seed, hostname-group holdout split, and deterministic gzip metadata.

## Main checks

- public-target validation and redirect SSRF protection
- URL-language, structure, entropy, homograph, punycode, and typosquatting signals
- domain age, WHOIS, DNS, TLS, and redirect analysis
- form and JavaScript behavior
- security and response headers, cookies, CORS, and mixed content
- robots.txt, sitemap, file-exposure, HTTP-method, and technology observations
- VirusTotal reputation and category data
- private per-session history and downloadable PDF reports

## Project structure

```text
URL-Security-Analyzer/
├── analyzer/
│   ├── data/                         # versioned model and policies
│   ├── detection_manager.py          # complete-only orchestration
│   ├── risk_engine.py                # calibrated threat and posture logic
│   └── ...                           # focused checkers
├── database/
├── scripts/train_url_language_model.py
├── static/
├── templates/
├── tests/
├── app.py
└── requirements.txt
```

## Install and run

```bash
git clone https://github.com/abhianitha2007-dotcom/URL-Security-Analyzer.git
cd URL-Security-Analyzer
python -m venv .venv
```

Activate the environment, then install dependencies:

```bash
python -m pip install -r requirements.txt
```

Copy `.env.example` to `.env` and replace every placeholder:

```env
SECRET_KEY=replace-with-a-long-random-value
VIRUSTOTAL_API_KEY=replace-with-your-virustotal-api-key
FLASK_DEBUG=false
SESSION_COOKIE_SECURE=false
```

Use `SESSION_COOKIE_SECURE=true` behind production HTTPS.

Start locally:

```bash
python app.py
```

Production command:

```bash
gunicorn app:app
```

## Test

```bash
python -m pytest tests -q
```

The suite covers deterministic snapshot reuse, complete-only failures, scoring regressions, content-warning separation, model repeatability, Flask routes, CSRF, SSRF defenses, history isolation, and PDF routes.

## Security notes

- Never commit `.env`, API keys, or generated reports.
- Submitted URLs may be looked up or submitted to VirusTotal for reputation analysis.
- If a credential has ever been committed, deleting it from the current file is not sufficient; revoke and rotate it.
- Outbound requests validate the original host and every redirect target against public-address rules.
- The app sends a restrictive Content Security Policy and other browser security headers.
- This project is intended for defensive and educational use.

## License

MIT
