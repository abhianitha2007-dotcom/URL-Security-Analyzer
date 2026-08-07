import requests
from analyzer.safe_http import safe_requests


RISKY_METHODS = {
    "TRACE",
    "TRACK"
}


COMMON_METHODS = {
    "GET",
    "HEAD",
    "POST",
    "OPTIONS"
}


def parse_allow_header(value):
    """
    Converts an Allow header into a clean list
    of HTTP methods.
    """

    if not value:
        return []

    methods = []

    for item in value.split(","):
        method = item.strip().upper()

        if method:
            methods.append(method)

    return sorted(
        set(methods)
    )


def check_http_methods(url):
    """
    Checks HTTP methods advertised by the server.

    Returns:
        {
            status,
            score,
            status_code,
            allowed_methods,
            risky_methods,
            unusual_methods
        }
    """

    result = {
        "status": "Not Checked",
        "score": 0,
        "status_code": None,
        "allowed_methods": [],
        "risky_methods": [],
        "unusual_methods": []
    }

    try:
        response = safe_requests.options(
            url,
            timeout=6,
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

        allow_header = response.headers.get(
            "Allow",
            ""
        )

        methods = parse_allow_header(
            allow_header
        )

        result["allowed_methods"] = methods

        risky = [
            method
            for method in methods
            if method in RISKY_METHODS
        ]

        unusual = [
            method
            for method in methods
            if (
                method not in COMMON_METHODS
                and method not in RISKY_METHODS
            )
        ]

        result["risky_methods"] = risky
        result["unusual_methods"] = unusual

        score = 0

        if risky:
            score += 8

        if len(unusual) >= 3:
            score += 2

        result["score"] = min(
            score,
            10
        )

        if risky:
            result["status"] = (
                "🔴 Risky HTTP Methods Advertised"
            )

        elif unusual:
            result["status"] = (
                "🟡 Additional HTTP Methods Advertised"
            )

        elif methods:
            result["status"] = (
                "🟢 Standard HTTP Methods Advertised"
            )

        else:
            result["status"] = (
                "🟢 No HTTP Methods Advertised"
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