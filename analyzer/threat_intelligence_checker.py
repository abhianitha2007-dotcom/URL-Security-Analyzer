import os
import base64

from datetime import datetime

import requests

from dotenv import load_dotenv


# =========================================================
# ENVIRONMENT
# =========================================================

load_dotenv()


VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY"
)


VIRUSTOTAL_URL_ENDPOINT = (
    "https://www.virustotal.com/api/v3/urls"
)


# =========================================================
# URL ID
# =========================================================

def generate_url_id(url):
    """
    Generate VirusTotal URL identifier.

    VirusTotal uses URL-safe Base64 encoding
    without trailing '=' padding.
    """

    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("utf-8")

    return encoded.rstrip("=")


# =========================================================
# DATE FORMATTER
# =========================================================

def format_timestamp(timestamp):
    """
    Convert Unix timestamp into readable format.
    """

    if not timestamp:

        return "Unknown"


    try:

        return datetime.fromtimestamp(
            timestamp
        ).strftime(
            "%d-%m-%Y %H:%M:%S"
        )

    except (
        TypeError,
        ValueError,
        OverflowError
    ):

        return "Unknown"


# =========================================================
# DEFAULT RESULT
# =========================================================

def create_default_result():

    return {

        "checked": False,

        "report_found": False,

        "submitted": False,

        "analysis_id": None,

        "malicious": 0,

        "suspicious": 0,

        "harmless": 0,

        "undetected": 0,

        "timeout": 0,

        "total_engines": 0,

        "reputation": 0,

        "categories": [],

        "last_analysis_date": "Unknown",

        "score": 0,

        "issues": [],

        "status": "Not Checked",

        "source": "VirusTotal"
    }


# =========================================================
# API HEADERS
# =========================================================

def get_api_headers():

    return {

        "x-apikey":
            VIRUSTOTAL_API_KEY,

        "Accept":
            "application/json"
    }


# =========================================================
# SUBMIT UNKNOWN URL
# =========================================================

def submit_url_for_analysis(url):
    """
    Submit an unknown URL to VirusTotal.

    Does NOT poll for the finished result.

    Returns:
        analysis_id or None
    """

    if not VIRUSTOTAL_API_KEY:

        return None


    try:

        response = requests.post(

            VIRUSTOTAL_URL_ENDPOINT,

            headers=get_api_headers(),

            data={
                "url": url
            },

            timeout=12
        )


    except requests.RequestException:

        return None


    if response.status_code not in (
        200,
        201
    ):

        return None


    try:

        response_data = (
            response.json()
        )

    except ValueError:

        return None


    analysis_id = (

        response_data
        .get("data", {})
        .get("id")

    )


    return analysis_id


# =========================================================
# MAIN CHECKER
# =========================================================

def check_threat_intelligence(
    url,
    submit_if_unknown=True
):
    """
    Check a URL against VirusTotal.

    Process:

        1. Generate VirusTotal URL ID
        2. Search for existing report
        3. If found:
             return reputation information
        4. If not found:
             optionally submit URL
        5. Do NOT continuously poll VirusTotal

    This keeps API usage low.
    """

    result = create_default_result()


    # =====================================================
    # API KEY
    # =====================================================

    if not VIRUSTOTAL_API_KEY:

        result["status"] = (
            "⚪ Not Checked — "
            "VirusTotal API Key Missing"
        )

        return result


    # =====================================================
    # URL ID
    # =====================================================

    try:

        url_id = generate_url_id(
            url
        )

    except Exception:

        result["status"] = (
            "⚪ Not Checked — "
            "Unable to Encode URL"
        )

        return result


    endpoint = (
        f"{VIRUSTOTAL_URL_ENDPOINT}/{url_id}"
    )


    # =====================================================
    # LOOK UP EXISTING REPORT
    # =====================================================

    try:

        response = requests.get(

            endpoint,

            headers=get_api_headers(),

            timeout=12
        )


    except requests.Timeout:

        result["status"] = (
            "⚪ Not Checked — "
            "VirusTotal Request Timed Out"
        )

        return result


    except requests.RequestException:

        result["status"] = (
            "⚪ Not Checked — "
            "VirusTotal Request Failed"
        )

        return result


    # =====================================================
    # UNKNOWN URL
    # =====================================================

    if response.status_code == 404:

        result["checked"] = True


        if not submit_if_unknown:

            result["status"] = (
                "⚪ No Existing VirusTotal Report"
            )

            return result


        analysis_id = (
            submit_url_for_analysis(
                url
            )
        )


        if analysis_id:

            result["submitted"] = True

            result["analysis_id"] = (
                analysis_id
            )

            result["status"] = (
                "🔵 Submitted to VirusTotal "
                "for Analysis"
            )


        else:

            result["status"] = (
                "⚪ No Existing VirusTotal Report — "
                "Submission Failed"
            )


        return result


    # =====================================================
    # RATE LIMIT
    # =====================================================

    if response.status_code == 429:

        result["status"] = (
            "⚪ Not Checked — "
            "VirusTotal API Quota Exceeded"
        )

        return result


    # =====================================================
    # AUTHENTICATION
    # =====================================================

    if response.status_code == 401:

        result["status"] = (
            "⚪ Not Checked — "
            "VirusTotal Authentication Failed"
        )

        return result


    if response.status_code == 403:

        result["status"] = (
            "⚪ Not Checked — "
            "VirusTotal Permission Denied"
        )

        return result


    # =====================================================
    # OTHER ERRORS
    # =====================================================

    if response.status_code != 200:

        result["status"] = (

            "⚪ Not Checked — "
            f"VirusTotal API Error "
            f"({response.status_code})"

        )

        return result


    # =====================================================
    # RESPONSE JSON
    # =====================================================

    try:

        response_data = (
            response.json()
        )

    except ValueError:

        result["status"] = (
            "⚪ Not Checked — "
            "Invalid VirusTotal Response"
        )

        return result


    attributes = (

        response_data
        .get("data", {})
        .get("attributes", {})

    )


    if not attributes:

        result["status"] = (
            "⚪ VirusTotal Report "
            "Contains No Analysis Data"
        )

        return result


    # =====================================================
    # REPORT FOUND
    # =====================================================

    result["checked"] = True

    result["report_found"] = True


    # =====================================================
    # ANALYSIS STATS
    # =====================================================

    stats = attributes.get(

        "last_analysis_stats",

        {}

    ) or {}


    result["malicious"] = int(

        stats.get(
            "malicious",
            0
        ) or 0

    )


    result["suspicious"] = int(

        stats.get(
            "suspicious",
            0
        ) or 0

    )


    result["harmless"] = int(

        stats.get(
            "harmless",
            0
        ) or 0

    )


    result["undetected"] = int(

        stats.get(
            "undetected",
            0
        ) or 0

    )


    result["timeout"] = int(

        stats.get(
            "timeout",
            0
        ) or 0

    )


    # =====================================================
    # TOTAL ENGINES
    # =====================================================

    result["total_engines"] = sum(

        int(value or 0)

        for value in stats.values()

        if isinstance(
            value,
            (int, float)
        )

    )


    # =====================================================
    # REPUTATION
    # =====================================================

    reputation = attributes.get(
        "reputation",
        0
    )


    try:

        result["reputation"] = int(
            reputation
        )

    except (
        TypeError,
        ValueError
    ):

        result["reputation"] = 0


    # =====================================================
    # DATE
    # =====================================================

    result["last_analysis_date"] = (

        format_timestamp(

            attributes.get(
                "last_analysis_date"
            )

        )

    )


    # =====================================================
    # CATEGORIES
    # =====================================================

    categories = attributes.get(

        "categories",

        {}

    ) or {}


    unique_categories = []


    if isinstance(
        categories,
        dict
    ):

        for category in (
            categories.values()
        ):

            if not category:

                continue


            category = str(
                category
            ).strip()


            if (
                category
                and
                category not in unique_categories
            ):

                unique_categories.append(
                    category
                )


    result["categories"] = (
        unique_categories[:10]
    )


    # =====================================================
    # RISK CALCULATION
    # =====================================================

    malicious = (
        result["malicious"]
    )


    suspicious = (
        result["suspicious"]
    )


    score = 0


    # -----------------------------------------------------
    # MALICIOUS
    # -----------------------------------------------------

    if malicious >= 10:

        score = 40


    elif malicious >= 5:

        score = 35


    elif malicious >= 3:

        score = 30


    elif malicious == 2:

        score = 24


    elif malicious == 1:

        score = 15


    # -----------------------------------------------------
    # SUSPICIOUS
    # -----------------------------------------------------

    if suspicious >= 5:

        score += 10


    elif suspicious >= 2:

        score += 6


    elif suspicious == 1:

        score += 3


    result["score"] = min(
        score,
        45
    )


    # =====================================================
    # ISSUES
    # =====================================================

    if malicious > 0:

        result["issues"].append(

            (
                f"{malicious} security engine(s) "
                "classified this URL as malicious"
            )

        )


    if suspicious > 0:

        result["issues"].append(

            (
                f"{suspicious} security engine(s) "
                "classified this URL as suspicious"
            )

        )


    # =====================================================
    # FINAL STATUS
    # =====================================================

    if malicious >= 5:

        result["status"] = (
            "🔴 Known Malicious Reputation Detected"
        )


    elif malicious >= 2:

        result["status"] = (
            "🔴 Multiple Malicious Detections"
        )


    elif malicious == 1:

        result["status"] = (
            "🟠 One Security Vendor "
            "Flagged This URL"
        )


    elif suspicious >= 2:

        result["status"] = (
            "🟠 Multiple Suspicious "
            "Reputation Signals"
        )


    elif suspicious == 1:

        result["status"] = (
            "🟡 One Suspicious "
            "Reputation Signal"
        )


    else:

        result["status"] = (
            "🟢 No Malicious "
            "Reputation Detected"
        )


    return result