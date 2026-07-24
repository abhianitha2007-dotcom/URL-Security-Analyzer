from urllib.parse import urlparse


def check_https(url):
    """
    Checks whether a URL uses HTTPS.
    Returns:
        True  -> HTTPS
        False -> HTTP
    """

    parsed_url = urlparse(url)

    return parsed_url.scheme == "https"