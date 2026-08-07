import requests
from analyzer.safe_http import safe_requests


def check_cookie_security(url):
    """
    Analyze cookies returned by a website.

    Checks:
        - Secure attribute
        - HttpOnly attribute
        - SameSite attribute
        - Session cookies
        - Cookie count

    Returns:
        dict
    """

    result = {
        "found": False,
        "cookie_count": 0,
        "secure_count": 0,
        "httponly_count": 0,
        "samesite_count": 0,
        "session_cookie_count": 0,
        "issues": [],
        "cookies": [],
        "score": 0,
        "status": "Not Checked"
    }

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
                    "(KHTML, like Gecko) "
                    "Chrome/120 Safari/537.36"
                )
            }
        )

    except requests.RequestException:

        result["status"] = (
            "⚪ Not Checked — Request Failed"
        )

        return result


    # -------------------------------------------------
    # COOKIE COLLECTION
    # -------------------------------------------------

    cookies = response.cookies


    if not cookies:

        result["status"] = (
            "🟢 No Cookies Detected"
        )

        return result


    result["found"] = True

    result["cookie_count"] = len(cookies)


    # -------------------------------------------------
    # ANALYZE EACH COOKIE
    # -------------------------------------------------

    for cookie in cookies:

        cookie_data = {
            "name": cookie.name,
            "domain": cookie.domain or "Unknown",
            "path": cookie.path or "/",
            "secure": bool(cookie.secure),
            "httponly": False,
            "samesite": "Not Set",
            "session": cookie.expires is None
        }


        """
        requests stores attributes such as HttpOnly
        and SameSite inside the cookie's _rest field.
        """

        rest = getattr(
            cookie,
            "_rest",
            {}
        ) or {}


        for key, value in rest.items():

            normalized_key = (
                str(key)
                .strip()
                .lower()
            )


            # -----------------------------
            # HttpOnly
            # -----------------------------

            if normalized_key == "httponly":

                cookie_data["httponly"] = True


            # -----------------------------
            # SameSite
            # -----------------------------

            elif normalized_key == "samesite":

                if value:

                    cookie_data["samesite"] = (
                        str(value)
                        .strip()
                        .lower()
                    )

                else:

                    cookie_data["samesite"] = "set"


        # -------------------------------------------------
        # COUNTERS
        # -------------------------------------------------

        if cookie_data["secure"]:

            result["secure_count"] += 1


        if cookie_data["httponly"]:

            result["httponly_count"] += 1


        if cookie_data["samesite"] != "Not Set":

            result["samesite_count"] += 1


        if cookie_data["session"]:

            result["session_cookie_count"] += 1


        result["cookies"].append(
            cookie_data
        )


    # -------------------------------------------------
    # GROUP COOKIE OBSERVATIONS
    # -------------------------------------------------

    insecure_cookies = [

        cookie

        for cookie in result["cookies"]

        if not cookie["secure"]

    ]


    missing_httponly = [

        cookie

        for cookie in result["cookies"]

        if not cookie["httponly"]

    ]


    missing_samesite = [

        cookie

        for cookie in result["cookies"]

        if cookie["samesite"] == "Not Set"

    ]


    # -------------------------------------------------
    # ISSUE MESSAGES
    # -------------------------------------------------

    if insecure_cookies:

        result["issues"].append(

            (
                f"{len(insecure_cookies)} "
                "cookie(s) do not use the "
                "Secure attribute"
            )

        )


    if missing_httponly:

        result["issues"].append(

            (
                f"{len(missing_httponly)} "
                "cookie(s) are accessible "
                "to client-side scripts"
            )

        )


    if missing_samesite:

        result["issues"].append(

            (
                f"{len(missing_samesite)} "
                "cookie(s) do not declare "
                "a SameSite policy"
            )

        )


    # -------------------------------------------------
    # RISK SCORING
    # -------------------------------------------------
    #
    # Cookie configuration is primarily a
    # web-security hardening signal.
    #
    # Missing HttpOnly or SameSite alone does
    # NOT mean the website is phishing.
    #
    # Therefore this checker contributes only
    # a very small amount to the overall URL
    # threat score.
    # -------------------------------------------------

    score = 0


    # HTTPS site returning cookies without
    # the Secure attribute is mildly relevant.
    if insecure_cookies:

        score += 1


    # Missing HttpOnly is informational.
    # It should not increase phishing risk.
    if missing_httponly:

        score += 0


    # Missing SameSite is also primarily
    # a security-hardening observation.
    if missing_samesite:

        score += 0


    result["score"] = min(
        score,
        2
    )


    # -------------------------------------------------
    # STATUS
    # -------------------------------------------------

    if not result["issues"]:

        result["status"] = (
            "🟢 Cookie Security Attributes Look Good"
        )


    elif insecure_cookies:

        result["status"] = (
            "🟡 Cookie Security Could Be Improved"
        )


    else:

        result["status"] = (
            "🟢 Cookies Detected — "
            "Minor Hardening Observations"
        )


    return result