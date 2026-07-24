from urllib.parse import urlparse
import ipaddress


def contains_ip(url):
    """
    Returns True if the hostname is an IP address.
    """

    try:
        hostname = urlparse(url).hostname

        ipaddress.ip_address(hostname)

        return True

    except ValueError:
        return False