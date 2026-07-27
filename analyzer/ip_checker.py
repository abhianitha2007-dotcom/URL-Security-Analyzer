from urllib.parse import urlparse
import ipaddress



def contains_ip(url):
    """
    Checks whether hostname is an IP address.

    Supports:
    - IPv4
    - IPv6

    Returns:
        True / False
    """

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname


        if not hostname:

            return False



        try:

            ipaddress.ip_address(hostname)

            return True


        except ValueError:

            return False



    except Exception:

        return False