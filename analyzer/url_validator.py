from urllib.parse import urlparse


def is_valid_url(url):
    """
    Returns True if the URL has
    a valid scheme and domain.
    """

    parsed = urlparse(url)

    return all([parsed.scheme, parsed.netloc])