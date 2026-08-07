import ipaddress
import socket
import time

import dns.exception
import dns.resolver

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


# Number of attempts made using the operating system DNS
# resolver before trying the fallback public resolvers.
SYSTEM_DNS_ATTEMPTS = 3


# Short delays between temporary system DNS failures.
DNS_RETRY_DELAYS = (
    0.15,
    0.35
)


# Used only when the operating system resolver temporarily
# fails. These are public DNS resolvers.
FALLBACK_NAMESERVERS = (
    "1.1.1.1",
    "8.8.8.8"
)


# =========================================================
# IP ADDRESS VALIDATION
# =========================================================

def _is_public_ip(value):
    """
    Return True only for globally routable IP addresses.

    This blocks:

        - loopback
        - private networks
        - link-local addresses
        - multicast
        - reserved ranges
        - unspecified addresses
        - other non-public special-use addresses
    """

    try:

        ip = ipaddress.ip_address(
            value
        )

    except ValueError:

        return False


    # -----------------------------------------------------
    # IPv4-MAPPED IPv6
    #
    # Example:
    #
    # ::ffff:127.0.0.1
    # -----------------------------------------------------

    if (
        isinstance(
            ip,
            ipaddress.IPv6Address
        )
        and ip.ipv4_mapped is not None
    ):

        ip = ip.ipv4_mapped


    return ip.is_global


# =========================================================
# HOSTNAME NORMALIZATION
# =========================================================

def _normalize_hostname(
    hostname
):
    """
    Normalize a hostname before validation.

    Converts internationalized hostnames to their ASCII
    IDNA form and removes a trailing dot.
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


# =========================================================
# LOCAL HOSTNAME BLOCKING
# =========================================================

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


# =========================================================
# LITERAL IP VALIDATION
# =========================================================

def _validate_literal_ip(
    hostname
):
    """
    Validate a hostname when the hostname itself is an
    IP address.

    Returns:

        True
            The IP address is globally routable.

        False
            The IP address is private, local, reserved,
            link-local or otherwise non-public.

        None
            The hostname is not an IP literal.
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


# =========================================================
# DNS RESULT VALIDATION
# =========================================================

def _all_resolved_ips_are_public(
    resolved_ips
):
    """
    Validate a collection of resolved IP addresses.

    Every returned address must be public.

    If even one resolved address points to a private,
    local, reserved or otherwise non-global network,
    the hostname is rejected.
    """

    if not resolved_ips:

        return False


    return all(
        _is_public_ip(
            ip_value
        )
        for ip_value in resolved_ips
    )


# =========================================================
# SYSTEM DNS RESOLUTION
# =========================================================

def _resolve_with_system_dns(
    hostname,
    port
):
    """
    Resolve a hostname using the operating system DNS
    resolver.

    Temporary DNS failures are retried a small number of
    times.

    Returns:

        set
            Resolved IP addresses.

        None
            DNS resolution failed.
    """

    for attempt in range(
        SYSTEM_DNS_ATTEMPTS
    ):

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

            # -------------------------------------------------
            # Retry temporary DNS failures.
            # -------------------------------------------------

            if (
                attempt
                < len(
                    DNS_RETRY_DELAYS
                )
            ):

                time.sleep(
                    DNS_RETRY_DELAYS[
                        attempt
                    ]
                )

            continue


        resolved_ips = set()


        for address in addresses:

            try:

                sockaddr = address[4]

            except (
                IndexError,
                TypeError
            ):

                continue


            if not sockaddr:

                continue


            try:

                ip_value = sockaddr[0]

            except (
                IndexError,
                TypeError
            ):

                continue


            if ip_value:

                resolved_ips.add(
                    str(
                        ip_value
                    )
                )


        if resolved_ips:

            return resolved_ips


    return None


# =========================================================
# FALLBACK DNS RESOLUTION
# =========================================================

def _resolve_with_fallback_dns(
    hostname
):
    """
    Resolve a hostname using public DNS resolvers when the
    operating system resolver is temporarily unavailable.

    This does NOT bypass SSRF protection.

    Every returned IP address is still checked by
    _is_public_ip() before the URL can be accepted.
    """

    resolver = dns.resolver.Resolver(
        configure=False
    )


    resolver.nameservers = list(
        FALLBACK_NAMESERVERS
    )


    resolver.timeout = 2.0
    resolver.lifetime = 4.0


    resolved_ips = set()


    # -----------------------------------------------------
    # IPV4
    # -----------------------------------------------------

    try:

        answers = resolver.resolve(
            hostname,
            "A"
        )


        for answer in answers:

            ip_value = getattr(
                answer,
                "address",
                None
            )


            if ip_value:

                resolved_ips.add(
                    str(
                        ip_value
                    )
                )


    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
        OSError
    ):

        pass


    # -----------------------------------------------------
    # IPV6
    # -----------------------------------------------------

    try:

        answers = resolver.resolve(
            hostname,
            "AAAA"
        )


        for answer in answers:

            ip_value = getattr(
                answer,
                "address",
                None
            )


            if ip_value:

                resolved_ips.add(
                    str(
                        ip_value
                    )
                )


    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
        OSError
    ):

        pass


    if not resolved_ips:

        return None


    return resolved_ips


# =========================================================
# PUBLIC HOSTNAME RESOLUTION
# =========================================================

def _resolve_public_hostname(
    hostname,
    port
):
    resolved_ips = _resolve_with_system_dns(
        hostname,
        port
    )

    print(
        f"[DNS DEBUG] System DNS for {hostname}: "
        f"{resolved_ips}",
        flush=True
    )

    if resolved_ips is None:

        resolved_ips = (
            _resolve_with_fallback_dns(
                hostname
            )
        )

        print(
            f"[DNS DEBUG] Fallback DNS for {hostname}: "
            f"{resolved_ips}",
            flush=True
        )

    if not resolved_ips:

        print(
            f"[DNS DEBUG] No usable DNS result for {hostname}",
            flush=True
        )

        return False

    public_result = (
        _all_resolved_ips_are_public(
            resolved_ips
        )
    )

    print(
        f"[DNS DEBUG] Public-IP validation for {hostname}: "
        f"{public_result} | IPs={resolved_ips}",
        flush=True
    )

    return public_result

    # -----------------------------------------------------
    # SYSTEM DNS FAILED
    # -----------------------------------------------------

    if resolved_ips is None:

        resolved_ips = (
            _resolve_with_fallback_dns(
                hostname
            )
        )


    if not resolved_ips:

        return False


    return _all_resolved_ips_are_public(
        resolved_ips
    )


# =========================================================
# MAIN URL VALIDATOR
# =========================================================

def is_valid_url(
    url
):
    """
    Validate whether a URL is suitable for scanning.

    Requirements:

        - HTTP or HTTPS only
        - valid hostname
        - no embedded username/password
        - valid TCP port
        - no localhost hostnames
        - no private/local/reserved IP targets
        - resolved addresses must be globally routable

    DNS resolution includes retry handling and a public
    DNS fallback for environments where the operating
    system resolver temporarily fails.

    Returns:
        bool
    """

    # -----------------------------------------------------
    # INPUT TYPE
    # -----------------------------------------------------

    if not isinstance(
        url,
        str
    ):

        return False


    url = url.strip()


    if not url:

        return False


    # -----------------------------------------------------
    # URL PARSING
    # -----------------------------------------------------

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
    # NETWORK LOCATION
    # -----------------------------------------------------

    if not parsed.netloc:

        return False


    # -----------------------------------------------------
    # HOSTNAME
    # -----------------------------------------------------

    try:

        hostname = _normalize_hostname(
            parsed.hostname
        )

    except ValueError:

        return False


    if not hostname:

        return False


    # -----------------------------------------------------
    # USERNAME / PASSWORD
    #
    # Reject URLs such as:
    #
    # https://trusted.example@evil.example/
    #
    # They can visually mislead users and are unnecessary
    # for this security scanner.
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
    # DNS / SSRF VALIDATION
    # -----------------------------------------------------

    return _resolve_public_hostname(
        hostname,
        port
    )