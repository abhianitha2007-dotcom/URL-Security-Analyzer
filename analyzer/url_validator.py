from urllib.parse import urlparse


def is_valid_url(url):
    """
    Validates whether the URL has:
    - http or https scheme
    - a valid hostname
    - at least one dot in the domain

    Returns:
        True / False
    """

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.netloc:
            return False

        hostname = parsed.hostname

        if hostname is None:
            return False

        # Require at least one dot
        if "." not in hostname:
            return False

        return True

    except Exception:
        return False