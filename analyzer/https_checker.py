from urllib.parse import urlparse



def check_https(url):
    """
    Checks whether URL uses HTTPS.

    Returns:
        True  -> HTTPS
        False -> HTTP or invalid
    """

    try:

        parsed = urlparse(url)


        scheme = parsed.scheme.lower()


        if scheme == "https":

            return True


        return False



    except Exception:

        return False