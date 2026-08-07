import requests
from analyzer.safe_http import safe_requests


SECURITY_HEADERS = {
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
}


def check_security_headers(url):

    """
    Returns:
        missing_headers,
        status,
        score
    """

    try:
        response = safe_requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        missing_headers = [
            header
            for header in SECURITY_HEADERS
            if not response.headers.get(header)
        ]

        missing_count = len(missing_headers)

        if missing_count == 0:
            return (
                [],
                "🟢 Recommended Security Headers Present",
                0
            )

        if missing_count <= 2:
            return (
                missing_headers,
                "🟢 Minor Security Header Gaps",
                0
            )

        if missing_count <= 4:
            return (
                missing_headers,
                "🟡 Several Security Headers Missing",
                0
            )

        return (
            missing_headers,
            "🟡 Most Security Headers Missing",
            0
        )

    except requests.RequestException:
        return (
            [],
            "Not Checked",
            0
        )

    except Exception:
        return (
            [],
            "Not Checked",
            0
        )