from urllib.parse import urlparse
import ipaddress


def contains_ip(url):

    """
    Checks whether the hostname is
    an IPv4 or IPv6 address.

    Returns

        True
        False

    """

    try:

        if not url:

            return False

        hostname = urlparse(url).hostname

        if not hostname:

            return False

        hostname = hostname.strip()

        try:

            ipaddress.ip_address(hostname)

            return True

        except ValueError:

            return False

    except Exception:

        return False