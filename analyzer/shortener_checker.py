from urllib.parse import urlparse

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc"
    "rb.gy"
    "lnkd.in"
    "trib.al"
    "shorte.st"
    "adf.ly"
]


def check_shortener(url):
    """
    Returns:
        found
        status
        score
    """

    hostname = urlparse(url).hostname

    if hostname is None:
        return False, "Not Checked", 0

    hostname = hostname.lower()

    for service in SHORTENERS:
        if hostname == service:
            return True, f"⚠️ URL Shortener Detected ({service})", 20

    return False, "✅ No URL Shortener", 0