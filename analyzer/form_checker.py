from urllib.parse import urljoin, urlparse

import requests
from analyzer.safe_http import safe_requests
from bs4 import BeautifulSoup


def get_hostname(url):

    try:
        return urlparse(url).hostname or ""

    except Exception:
        return ""


def is_cross_domain_action(page_url, action_url):

    page_host = get_hostname(page_url).lower()
    action_host = get_hostname(action_url).lower()

    if not action_host:
        return False

    return page_host != action_host


def check_forms(url):

    """
    Checks HTML forms for phishing indicators.

    Returns:
        detected_issues,
        status,
        score
    """

    try:
        response = safe_requests.get(
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
            return (
                [],
                "Not Checked",
                0
            )

        soup = BeautifulSoup(
            response.text[:1_000_000],
            "html.parser"
        )

        forms = soup.find_all("form")

        if not forms:
            return (
                [],
                "🟢 No HTML Forms Detected",
                0
            )

        detected = []
        score = 0

        for form in forms:
            action = form.get("action", "").strip()
            method = form.get("method", "get").lower()

            password_fields = form.find_all(
                "input",
                {"type": "password"}
            )

            hidden_fields = form.find_all(
                "input",
                {"type": "hidden"}
            )

            if password_fields:
                detected.append("password_form")

            if action:
                absolute_action = urljoin(
                    response.url,
                    action
                )

                if is_cross_domain_action(
                    response.url,
                    absolute_action
                ):
                    detected.append(
                        "cross_domain_form_action"
                    )

            if method == "get" and password_fields:
                detected.append(
                    "password_sent_using_get"
                )

            if len(hidden_fields) >= 10:
                detected.append(
                    "many_hidden_fields"
                )

        detected = sorted(set(detected))

        if "cross_domain_form_action" in detected:
            score += 15

        if "password_sent_using_get" in detected:
            score += 15

        if "password_form" in detected:
            score += 3

        if "many_hidden_fields" in detected:
            score += 4

        score = min(score, 30)

        if score >= 20:
            status = "🔴 Highly Suspicious Form Behaviour"

        elif score >= 8:
            status = "🟠 Suspicious Form Behaviour"

        elif detected:
            status = "🟡 Login or Data-Entry Form Detected"

        else:
            status = "🟢 No Suspicious Form Behaviour"

        return (
            detected,
            status,
            score
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