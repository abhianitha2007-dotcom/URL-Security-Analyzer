from urllib.parse import urlparse


def check_https(url):

    """
    Checks whether the URL uses HTTPS.

    Returns

        True  -> HTTPS
        False -> HTTP, invalid or unsupported

    """

    try:

        if not url:

            return False

        parsed = urlparse(url)

        scheme = parsed.scheme.lower()

        hostname = parsed.hostname

        if not hostname:

            return False

        if scheme != "https":

            return False

        return True

    except Exception:

        return False