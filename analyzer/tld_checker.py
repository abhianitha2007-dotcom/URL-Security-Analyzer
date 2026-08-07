from urllib.parse import urlparse


# ==========================================================
# High Risk TLDs
# Frequently abused in phishing campaigns
# ==========================================================

HIGH_RISK_TLDS = {

    "tk",
    "ml",
    "ga",
    "cf",
    "gq",

    "top",
    "click",
    "zip",
    "country",
    "stream",
    "cam",
    "rest",
    "fit",
    "kim",
    "men"

}


# ==========================================================
# Medium Risk TLDs
# ==========================================================

MEDIUM_RISK_TLDS = {

    "xyz",
    "live",
    "buzz",
    "work",
    "review",
    "support",
    "shop",
    "monster",
    "party",
    "loan",
    "download"

}


# ==========================================================
# Trusted Government Domains
# ==========================================================

GOVERNMENT_SUFFIXES = (

    ".gov",
    ".gov.in",
    ".nic.in"

)


# ==========================================================
# Trusted Educational Domains
# ==========================================================

EDUCATION_SUFFIXES = (

    ".edu",
    ".edu.in",
    ".ac.in"

)


# ==========================================================
# Military Domains
# ==========================================================

MILITARY_SUFFIXES = (

    ".mil",

)


# ==========================================================
# Banking Domains
# (Common banking suffixes)
# ==========================================================

BANKING_SUFFIXES = (

    ".bank",

)


# ==========================================================
# Extract Hostname
# ==========================================================

def extract_hostname(url):

    try:

        hostname = urlparse(url).hostname

        if hostname:

            return hostname.lower()

        return None

    except Exception:

        return None


# ==========================================================
# Check TLD
# ==========================================================

def check_tld(url):

    """
    Returns

    (
        tld,
        status,
        score
    )
    """

    try:

        hostname = extract_hostname(url)

        if not hostname:

            return (

                "Unknown",
                "Not Checked",
                0

            )

        # ---------------------------------
        # Government
        # ---------------------------------

        if hostname.endswith(GOVERNMENT_SUFFIXES):

            return (

                "Government",

                "✅ Official Government Domain",

                0

            )

        # ---------------------------------
        # Education
        # ---------------------------------

        if hostname.endswith(EDUCATION_SUFFIXES):

            return (

                "Education",

                "✅ Educational Institution",

                0

            )

        # ---------------------------------
        # Military
        # ---------------------------------

        if hostname.endswith(MILITARY_SUFFIXES):

            return (

                "Military",

                "✅ Military Domain",

                0

            )

        # ---------------------------------
        # Banking
        # ---------------------------------

        if hostname.endswith(BANKING_SUFFIXES):

            return (

                "Bank",

                "✅ Banking Domain",

                0

            )

        # ---------------------------------
        # Normal TLD
        # ---------------------------------

        parts = hostname.split(".")

        if len(parts) < 2:

            return (

                "Unknown",

                "Invalid Domain",

                0

            )

        tld = parts[-1]

        # ---------------------------------
        # High Risk
        # ---------------------------------

        if tld in HIGH_RISK_TLDS:

            return (

                tld,

                f"🔴 High-Risk TLD (.{tld})",

                20

            )

        # ---------------------------------
        # Medium Risk
        # ---------------------------------

        if tld in MEDIUM_RISK_TLDS:

            return (

                tld,

                f"🟡 Medium-Risk TLD (.{tld})",

                10

            )

        # ---------------------------------
        # Common
        # ---------------------------------

        return (

            tld,

            f"🟢 Common TLD (.{tld})",

            0

        )

    except Exception:

        return (

            "Unknown",

            "Not Checked",

            0

        )