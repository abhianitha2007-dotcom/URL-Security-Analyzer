import ipaddress
import socket

from urllib.parse import urlparse


# =========================================================
# URL VALIDATION / SSRF INPUT PROTECTION
# =========================================================

ALLOWED_SCHEMES = {
    "http",
    "https"
}


BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback"
}


BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local"
)


def _is_public_ip(value):
    """
    Return True only for globally routable IP addresses.

    This blocks:
        loopback
        private networks
        link-local addresses
        multicast
        reserved ranges
        unspecified addresses
        other non-public special-use addresses
    """

    try:

        ip = ipaddress.ip_address(
            value
        )

    except ValueError:

        return False


    # Handle IPv4-mapped IPv6 addresses such as:
    # ::ffff:127.0.0.1

    if (
        isinstance(
            ip,
            ipaddress.IPv6Address
        )
        and ip.ipv4_mapped is not None
    ):

        ip = ip.ipv4_mapped


    return ip.is_global


def _normalize_hostname(
    hostname
):
    """
    Normalize a hostname for validation.
    """

    if not hostname:

        return None


    hostname = str(
        hostname
    ).strip().rstrip(".").lower()


    if not hostname:

        return None


    try:

        hostname = hostname.encode(
            "idna"
        ).decode(
            "ascii"
        )

    except UnicodeError:

        return None


    return hostname


def _hostname_is_blocked(
    hostname
):
    """
    Block localhost and common local-only hostname forms.
    """

    if hostname in BLOCKED_HOSTNAMES:

        return True


    return hostname.endswith(
        BLOCKED_HOST_SUFFIXES
    )


def _validate_literal_ip(
    hostname
):
    """
    Validate a hostname when it is directly an IP address.

    Returns:
        True  -> public IP
        False -> non-public IP
        None  -> hostname is not an IP literal
    """

    try:

        ipaddress.ip_address(
            hostname
        )

    except ValueError:

        return None


    return _is_public_ip(
        hostname
    )


def _resolve_public_hostname(
    hostname,
    port
):
    """
    Resolve a hostname and ensure every returned address
    is globally routable.

    Rejecting the host when any resolved address is
    non-public prevents obvious DNS-based access to
    localhost/private infrastructure.
    """

    try:

        addresses = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM
        )

    except (
        socket.gaierror,
        OSError
    ):

        return False


    resolved_ips = set()


    for address in addresses:

        sockaddr = address[4]


        if not sockaddr:
            continue


        ip_value = sockaddr[0]


        if ip_value:

            resolved_ips.add(
                ip_value
            )


    if not resolved_ips:

        return False


    return all(
        _is_public_ip(ip_value)
        for ip_value in resolved_ips
    )


def is_valid_url(
    url
):
    """
    Validate whether a URL is suitable for scanning.

    Requirements:
        - http:// or https:// only
        - valid hostname
        - no embedded username/password
        - valid port syntax
        - no localhost/private/link-local/reserved targets
        - hostname must resolve only to public IP addresses

    Returns:
        bool
    """

    if not isinstance(
        url,
        str
    ):

        return False


    url = url.strip()


    if not url:

        return False


    try:

        parsed = urlparse(
            url
        )

    except ValueError:

        return False


    # -----------------------------------------------------
    # SCHEME
    # -----------------------------------------------------

    scheme = (
        parsed.scheme
        or ""
    ).lower()


    if scheme not in ALLOWED_SCHEMES:

        return False


    # -----------------------------------------------------
    # NETWORK LOCATION / HOSTNAME
    # -----------------------------------------------------

    if not parsed.netloc:

        return False


    try:

        hostname = _normalize_hostname(
            parsed.hostname
        )

    except ValueError:

        return False


    if not hostname:

        return False


    # -----------------------------------------------------
    # USERINFO
    #
    # URLs such as:
    #
    # https://trusted.example@evil.example/
    #
    # can visually mislead users and are unnecessary for
    # this scanner, so credentials embedded in URLs are
    # rejected.
    # -----------------------------------------------------

    if (
        parsed.username is not None
        or parsed.password is not None
    ):

        return False


    # -----------------------------------------------------
    # PORT
    # -----------------------------------------------------

    try:

        parsed_port = parsed.port

    except ValueError:

        return False


    port = parsed_port


    if port is None:

        port = (
            443
            if scheme == "https"
            else 80
        )


    if not (
        1
        <= port
        <= 65535
    ):

        return False


    # -----------------------------------------------------
    # LOCAL HOSTNAME BLOCK
    # -----------------------------------------------------

    if _hostname_is_blocked(
        hostname
    ):

        return False


    # -----------------------------------------------------
    # DIRECT IP ADDRESS
    # -----------------------------------------------------

    literal_ip_result = (
        _validate_literal_ip(
            hostname
        )
    )


    if literal_ip_result is not None:

        return literal_ip_result


    # -----------------------------------------------------
    # DNS RESOLUTION
    # -----------------------------------------------------

    return _resolve_public_hostname(
        hostname,
        port
    )