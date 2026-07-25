from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "account",
    "password",
    "signin",
    "confirm"
]


def check_keywords(url):
    """
    Returns:
        count -> number of suspicious keywords
        found -> list of matched keywords
    """

    parsed = urlparse(url)

    text = (
        parsed.netloc.lower()
        + parsed.path.lower()
        + parsed.query.lower()
    )

    found = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            found.append(keyword)

    return len(found), found