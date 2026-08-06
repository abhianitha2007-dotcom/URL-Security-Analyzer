import base64
import re

import requests
from bs4 import BeautifulSoup


HIGH_RISK_PATTERNS = {
    "eval": r"\beval\s*\(",
    "long_hex_sequence": r"(?:\\x[0-9a-fA-F]{2}){12,}",
    "document_cookie_assignment": r"document\.cookie\s*="
}


MEDIUM_RISK_PATTERNS = {
    "atob": r"\batob\s*\(",
    "document_write": r"document\.write\s*\(",
    "location_replace": r"location\.replace\s*\("
}


INFORMATIONAL_PATTERNS = {
    "hidden_iframe": (
        r"<iframe[^>]+"
        r"(?:display\s*:\s*none|visibility\s*:\s*hidden)"
    ),
    "from_char_code": r"String\.fromCharCode\s*\(",
    "window_location": r"window\.location",
    "location_href": r"location\.href",
    "set_timeout": r"setTimeout\s*\(",
    "javascript_url": r"javascript\s*:"
}

def fetch_page(url):

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
            return None

        return response.text[:1_000_000]

    except requests.RequestException:
        return None


def extract_javascript(html):

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    scripts = []

    for script in soup.find_all("script"):
        text = script.get_text()

        if text:
            scripts.append(text)

    return "\n".join(scripts)


def detect_base64_content(script_text):

    matches = re.findall(
        r"[A-Za-z0-9+/]{120,}={0,2}",
        script_text
    )

    for value in matches:
        try:
            decoded = base64.b64decode(
                value,
                validate=True
            )

            decoded_text = decoded.decode(
                "utf-8",
                errors="ignore"
            ).lower()

            suspicious_terms = (
                "<script",
                "eval(",
                "document.cookie",
                "window.location",
                "password"
            )

            if any(
                term in decoded_text
                for term in suspicious_terms
            ):
                return True

        except Exception:
            continue

    return False


def find_patterns(text, patterns):

    found = []

    for name, pattern in patterns.items():
        if re.search(
            pattern,
            text,
            re.IGNORECASE
        ):
            found.append(name)

    return found


def check_javascript(url):

    """
    Returns:
        detected_patterns,
        status,
        score
    """

    try:
        html = fetch_page(url)

        if html is None:
            return (
                [],
                "Not Checked",
                0
            )

        javascript = extract_javascript(html)

        combined_text = html + "\n" + javascript

        high_risk = find_patterns(
            combined_text,
            HIGH_RISK_PATTERNS
        )

        medium_risk = find_patterns(
            combined_text,
            MEDIUM_RISK_PATTERNS
        )

        informational = find_patterns(
            combined_text,
            INFORMATIONAL_PATTERNS
        )

        if detect_base64_content(javascript):
            high_risk.append(
                "suspicious_base64_script"
            )

        high_risk = sorted(set(high_risk))
        medium_risk = sorted(set(medium_risk))
        informational = sorted(set(informational))

        detected = (
            high_risk
            + medium_risk
            + informational
        )

        score = (
            len(high_risk) * 10
            + len(medium_risk) * 3
        )

        # Informational patterns do not add risk alone.
        if high_risk or len(medium_risk) >= 2:
            score += min(
                len(informational),
                2
            )

        score = min(score, 30)

        if score >= 20:
            status = "🔴 Highly Suspicious JavaScript"

        elif score >= 8:
            status = "🟠 Suspicious JavaScript Behaviour"

        elif score > 0:
            status = "🟡 JavaScript Requires Attention"

        elif informational:
            status = "🟢 Common JavaScript Behaviour Detected"

        else:
            status = "🟢 No Suspicious JavaScript Detected"

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