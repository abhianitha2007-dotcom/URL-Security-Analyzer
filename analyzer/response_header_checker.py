import re

import requests
from analyzer.safe_http import safe_requests


SECURITY_HEADERS = {
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
}


DISCLOSURE_HEADERS = {
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version"
}


OUTDATED_PATTERNS = {
    "apache": [
        r"Apache/2\.0",
        r"Apache/2\.2"
    ],
    "php": [
        r"PHP/5\.",
        r"PHP/7\.0"
    ],
    "iis": [
        r"Microsoft-IIS/6",
        r"Microsoft-IIS/7"
    ]
}


def detect_outdated_software(value):
    """
    Checks response header values for
    obvious outdated technology versions.
    """

    if not value:
        return []

    detected = []

    for technology, patterns in OUTDATED_PATTERNS.items():

        for pattern in patterns:

            if re.search(
                pattern,
                value,
                re.IGNORECASE
            ):
                detected.append(
                    technology
                )

                break

    return sorted(
        set(detected)
    )


def check_response_headers(url):
    """
    Analyzes HTTP response headers.

    Returns:

        {
            status,
            score,
            status_code,
            server,
            powered_by,
            content_type,
            cache_control,
            security_headers,
            missing_security_headers,
            disclosure_headers,
            outdated_software
        }
    """

    result = {
        "status": "Not Checked",
        "score": 0,
        "status_code": None,

        "server": "Unknown",
        "powered_by": "Unknown",
        "content_type": "Unknown",
        "cache_control": "Unknown",

        "security_headers": {},
        "missing_security_headers": [],

        "disclosure_headers": {},
        "outdated_software": []
    }

    try:

        response = safe_requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(compatible; URLSecurityAnalyzer/2.0)"
                )
            }
        )

        result["status_code"] = (
            response.status_code
        )

        headers = response.headers

        result["server"] = headers.get(
            "Server",
            "Unknown"
        )

        result["powered_by"] = headers.get(
            "X-Powered-By",
            "Unknown"
        )

        result["content_type"] = headers.get(
            "Content-Type",
            "Unknown"
        )

        result["cache_control"] = headers.get(
            "Cache-Control",
            "Unknown"
        )

        # ==========================================
        # SECURITY HEADERS
        # ==========================================

        security_headers = {}

        missing_security_headers = []

        for header in SECURITY_HEADERS:

            value = headers.get(
                header
            )

            if value:
                security_headers[header] = value

            else:
                missing_security_headers.append(
                    header
                )

        result["security_headers"] = (
            security_headers
        )

        result["missing_security_headers"] = (
            sorted(
                missing_security_headers
            )
        )

        # ==========================================
        # TECHNOLOGY DISCLOSURE
        # ==========================================

        disclosure_headers = {}

        for header in DISCLOSURE_HEADERS:

            value = headers.get(
                header
            )

            if value:
                disclosure_headers[header] = (
                    value
                )

        result["disclosure_headers"] = (
            disclosure_headers
        )

        disclosure_text = " ".join(
            disclosure_headers.values()
        )

        outdated = detect_outdated_software(
            disclosure_text
        )

        result["outdated_software"] = (
            outdated
        )

        # ==========================================
        # RISK CALCULATION
        # ==========================================

        score = 0

        # Header disclosure itself is mostly
        # informational.

        disclosure_count = len(
            disclosure_headers
        )

        if disclosure_count >= 3:
            score += 1

        # Missing security headers should remain
        # very low risk because this is hardening,
        # not phishing proof.

        missing_count = len(
            missing_security_headers
        )

        if missing_count >= 5:
            score += 1

        # Clearly outdated software disclosure
        # is more meaningful.

        if outdated:
            score += min(
                len(outdated) * 4,
                8
            )

        score = min(
            score,
            10
        )

        result["score"] = score

        # ==========================================
        # STATUS
        # ==========================================

        if outdated:

            result["status"] = (
                "🔴 Outdated Server Technology Detected"
            )

        elif disclosure_count >= 3:

            result["status"] = (
                "🟡 Multiple Technology Headers Exposed"
            )

        elif disclosure_count > 0:

            result["status"] = (
                "🟢 Minor Technology Disclosure"
            )

        elif missing_count >= 5:

            result["status"] = (
                "🟡 Security Header Hardening Recommended"
            )

        else:

            result["status"] = (
                "🟢 Response Headers Look Normal"
            )

        return result

    except requests.Timeout:

        result["status"] = (
            "Not Checked — Request Timed Out"
        )

        return result

    except requests.RequestException:

        result["status"] = (
            "Not Checked — Request Failed"
        )

        return result

    except Exception:

        result["status"] = "Not Checked"

        return result