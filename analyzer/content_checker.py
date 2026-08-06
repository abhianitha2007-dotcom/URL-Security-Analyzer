import re

import requests
from bs4 import BeautifulSoup


SUSPICIOUS_TEXT_PATTERNS = {
    "urgent_action": [
        "act immediately",
        "urgent action required",
        "verify now",
        "confirm immediately"
    ],
    "account_warning": [
        "account suspended",
        "account locked",
        "account blocked",
        "unusual activity"
    ],
    "credential_request": [
        "enter your password",
        "confirm your password",
        "verify your identity",
        "update your credentials"
    ],
    "financial_request": [
        "bank details",
        "credit card details",
        "payment required",
        "confirm payment"
    ]
}


def fetch_page_text(url):

    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "Chrome/120.0 Safari/537.36"
                )
            }
        )

        content_type = response.headers.get(
            "Content-Type",
            ""
        ).lower()

        if "text/html" not in content_type:
            return ""

        soup = BeautifulSoup(
            response.text[:1_000_000],
            "html.parser"
        )

        for element in soup([
            "script",
            "style",
            "noscript"
        ]):
            element.decompose()

        return soup.get_text(
            " ",
            strip=True
        ).lower()

    except requests.RequestException:
        return ""

    except Exception:
        return ""


def check_content(url):

    """
    Checks visible webpage text for
    common phishing language.

    Returns:
        detected_patterns,
        status,
        score
    """

    try:
        text = fetch_page_text(url)

        if not text:
            return (
                [],
                "Not Checked",
                0
            )

        detected = []

        for category, phrases in SUSPICIOUS_TEXT_PATTERNS.items():
            for phrase in phrases:
                pattern = rf"\b{re.escape(phrase)}\b"

                if re.search(
                    pattern,
                    text,
                    re.IGNORECASE
                ):
                    detected.append(category)
                    break

        detected = sorted(set(detected))

        score = len(detected) * 6
        score = min(score, 24)

        if score >= 18:
            status = "🔴 Strong Phishing Language Detected"

        elif score >= 8:
            status = "🟠 Suspicious Page Content"

        elif detected:
            status = "🟡 Potentially Suspicious Language"

        else:
            status = "🟢 No Suspicious Page Content"

        return (
            detected,
            status,
            score
        )

    except Exception:
        return (
            [],
            "Not Checked",
            0
        )