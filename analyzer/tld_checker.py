from urllib.parse import urlparse

# High-risk TLDs commonly abused in phishing
HIGH_RISK_TLDS = {
    "xyz",
    "top",
    "click",
    "gq",
    "cf",
    "ml",
    "tk",
    "ga"
}

# Medium-risk TLDs
MEDIUM_RISK_TLDS = {
    "work",
    "buzz",
    "live",
    "shop",
    "support",
    "review"
}


def check_tld(url):
    """
    Checks whether the domain uses a suspicious TLD.

    Returns:
        tld
        status
        score
    """

    hostname = urlparse(url).hostname

    if hostname is None:
        return "Unknown", "Not Checked", 0

    parts = hostname.lower().split(".")

    if len(parts) < 2:
        return "Unknown", "Invalid Domain", 0

    tld = parts[-1]

    if tld in HIGH_RISK_TLDS:
        return tld, f"🔴 High-Risk TLD (.{tld})", 25

    if tld in MEDIUM_RISK_TLDS:
        return tld, f"🟡 Medium-Risk TLD (.{tld})", 10

    return tld, f"🟢 Common TLD (.{tld})", 0