import requests
from analyzer.safe_http import safe_requests


TEST_ORIGIN = "https://evil-example.test"


def check_cors_security(url):
    """
    Analyze Cross-Origin Resource Sharing (CORS)
    configuration for the supplied URL.

    Checks:
        - Access-Control-Allow-Origin
        - Access-Control-Allow-Credentials
        - Access-Control-Allow-Methods
        - Access-Control-Allow-Headers
        - Access-Control-Expose-Headers
        - Arbitrary origin reflection

    Returns:
        dict
    """

    result = {
        "enabled": False,
        "allow_origin": "Not Set",
        "allow_credentials": False,
        "allow_methods": [],
        "allow_headers": [],
        "expose_headers": [],
        "origin_reflection": False,
        "issues": [],
        "score": 0,
        "status": "Not Checked"
    }

    headers = {
        "User-Agent": (
            "Mozilla/5.0 "
            "(Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/120 Safari/537.36"
        ),

        # Send a controlled test Origin header.
        "Origin": TEST_ORIGIN
    }

    try:

        response = safe_requests.get(
            url,
            headers=headers,
            timeout=8,
            allow_redirects=True
        )

    except requests.RequestException:

        result["status"] = (
            "⚪ Not Checked — Request Failed"
        )

        return result


    # ---------------------------------------------
    # READ CORS HEADERS
    # ---------------------------------------------

    allow_origin = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    allow_credentials = response.headers.get(
        "Access-Control-Allow-Credentials"
    )

    allow_methods = response.headers.get(
        "Access-Control-Allow-Methods"
    )

    allow_headers = response.headers.get(
        "Access-Control-Allow-Headers"
    )

    expose_headers = response.headers.get(
        "Access-Control-Expose-Headers"
    )


    # ---------------------------------------------
    # NO CORS
    # ---------------------------------------------

    if not any([
        allow_origin,
        allow_credentials,
        allow_methods,
        allow_headers,
        expose_headers
    ]):

        result["status"] = (
            "🟢 No CORS Policy Exposed"
        )

        return result


    result["enabled"] = True


    # ---------------------------------------------
    # ALLOWED ORIGIN
    # ---------------------------------------------

    if allow_origin:

        result["allow_origin"] = (
            allow_origin.strip()
        )


    # ---------------------------------------------
    # CREDENTIALS
    # ---------------------------------------------

    if allow_credentials:

        result["allow_credentials"] = (
            allow_credentials
            .strip()
            .lower()
            == "true"
        )


    # ---------------------------------------------
    # METHODS
    # ---------------------------------------------

    if allow_methods:

        result["allow_methods"] = [

            method.strip().upper()

            for method in allow_methods.split(",")

            if method.strip()

        ]


    # ---------------------------------------------
    # ALLOWED HEADERS
    # ---------------------------------------------

    if allow_headers:

        result["allow_headers"] = [

            header.strip()

            for header in allow_headers.split(",")

            if header.strip()

        ]


    # ---------------------------------------------
    # EXPOSED HEADERS
    # ---------------------------------------------

    if expose_headers:

        result["expose_headers"] = [

            header.strip()

            for header in expose_headers.split(",")

            if header.strip()

        ]


    # =================================================
    # SECURITY ANALYSIS
    # =================================================

    score = 0


    # ---------------------------------------------
    # Wildcard Origin
    # ---------------------------------------------

    if result["allow_origin"] == "*":

        result["issues"].append(
            "CORS allows requests from any origin"
        )

        score += 1


    # ---------------------------------------------
    # Arbitrary Origin Reflection
    # ---------------------------------------------

    if result["allow_origin"] == TEST_ORIGIN:

        result["origin_reflection"] = True

        result["issues"].append(
            "Server reflects arbitrary Origin values"
        )

        score += 3


    # ---------------------------------------------
    # Origin Reflection + Credentials
    # ---------------------------------------------

    if (
        result["origin_reflection"]
        and result["allow_credentials"]
    ):

        result["issues"].append(
            "Arbitrary origins may access credentialed responses"
        )

        score += 4


    # ---------------------------------------------
    # Wildcard + Credentials
    # ---------------------------------------------
    #
    # Browsers generally reject '*' with credentials,
    # but it still indicates poor CORS configuration.
    # ---------------------------------------------

    if (
        result["allow_origin"] == "*"
        and result["allow_credentials"]
    ):

        result["issues"].append(
            "Wildcard origin is combined with credential support"
        )

        score += 2


    # ---------------------------------------------
    # Risky HTTP Methods
    # ---------------------------------------------

    risky_methods = {
        "PUT",
        "DELETE",
        "PATCH"
    }


    detected_risky_methods = [

        method

        for method in result["allow_methods"]

        if method in risky_methods

    ]


    if detected_risky_methods:

        result["issues"].append(
            (
                "CORS advertises write-capable methods: "
                + ", ".join(detected_risky_methods)
            )
        )

        score += 1


    # ---------------------------------------------
    # Final checker score
    # ---------------------------------------------

    result["score"] = min(
        score,
        10
    )


    # =================================================
    # STATUS
    # =================================================

    if (
        result["origin_reflection"]
        and result["allow_credentials"]
    ):

        result["status"] = (
            "🔴 Potentially Dangerous CORS Configuration"
        )


    elif result["origin_reflection"]:

        result["status"] = (
            "🟠 Arbitrary Origin Reflection Detected"
        )


    elif result["issues"]:

        result["status"] = (
            "🟡 Permissive CORS Configuration"
        )


    else:

        result["status"] = (
            "🟢 CORS Configuration Looks Restricted"
        )


    return result