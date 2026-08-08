import ipaddress
import socket
import threading
import time

import dns.exception
import dns.resolver

from urllib.parse import urlparse


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

SYSTEM_DNS_ATTEMPTS = 3

DNS_RETRY_DELAYS = (
    0.15,
    0.35
)

FALLBACK_NAMESERVERS = (
    "1.1.1.1",
    "8.8.8.8"
)

_validation_state = threading.local()


def _set_result(
    valid,
    code,
    message,
    hostname=None
):
    result = {
        "valid": valid,
        "code": code,
        "message": message,
        "hostname": hostname
    }

    _validation_state.last_result = result

    return valid


def get_last_validation_result():
    return getattr(
        _validation_state,
        "last_result",
        {
            "valid": False,
            "code": "invalid_format",
            "message": (
                "Please enter a valid HTTP or HTTPS URL."
            ),
            "hostname": None
        }
    )


def _is_public_ip(value):
    try:
        ip = ipaddress.ip_address(
            value
        )
    except ValueError:
        return False

    if (
        isinstance(
            ip,
            ipaddress.IPv6Address
        )
        and ip.ipv4_mapped is not None
    ):
        ip = ip.ipv4_mapped

    return ip.is_global


def _normalize_hostname(hostname):
    if not hostname:
        return None

    hostname = (
        str(hostname)
        .strip()
        .rstrip(".")
        .lower()
    )

    if not hostname:
        return None

    try:
        return (
            hostname
            .encode("idna")
            .decode("ascii")
        )
    except UnicodeError:
        return None


def _hostname_syntax_valid(hostname):
    if not hostname:
        return False

    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    if len(labels) < 2:
        return False

    for label in labels:
        if not label:
            return False

        if len(label) > 63:
            return False

        if (
            label.startswith("-")
            or label.endswith("-")
        ):
            return False

        if not all(
            character.isalnum()
            or character == "-"
            for character in label
        ):
            return False

    return True


def _hostname_is_blocked(hostname):
    if hostname in BLOCKED_HOSTNAMES:
        return True

    return hostname.endswith(
        BLOCKED_HOST_SUFFIXES
    )


def _validate_literal_ip(hostname):
    try:
        ipaddress.ip_address(
            hostname
        )
    except ValueError:
        return None

    return _is_public_ip(
        hostname
    )


def _resolve_with_system_dns(
    hostname,
    port
):
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
            if attempt < len(
                DNS_RETRY_DELAYS
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
                ip_value = address[4][0]
            except (
                IndexError,
                TypeError
            ):
                continue

            if ip_value:
                resolved_ips.add(
                    str(ip_value)
                )

        if resolved_ips:
            return resolved_ips

    return None


def _resolve_with_fallback_dns(
    hostname
):
    resolver = dns.resolver.Resolver(
        configure=False
    )

    resolver.nameservers = list(
        FALLBACK_NAMESERVERS
    )

    resolver.timeout = 2.0
    resolver.lifetime = 4.0

    resolved_ips = set()

    for record_type in (
        "A",
        "AAAA"
    ):
        try:
            answers = resolver.resolve(
                hostname,
                record_type
            )

            for answer in answers:
                ip_value = getattr(
                    answer,
                    "address",
                    None
                )

                if ip_value:
                    resolved_ips.add(
                        str(ip_value)
                    )

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
            OSError
        ):
            continue

    return resolved_ips or None


def _resolve_hostname(
    hostname,
    port
):
    resolved_ips = (
        _resolve_with_system_dns(
            hostname,
            port
        )
    )

    if resolved_ips is None:
        resolved_ips = (
            _resolve_with_fallback_dns(
                hostname
            )
        )

    return resolved_ips


def is_valid_url(url):
    if not isinstance(
        url,
        str
    ):
        return _set_result(
            False,
            "invalid_format",
            "Please enter a valid HTTP or HTTPS URL."
        )

    url = url.strip()

    if not url:
        return _set_result(
            False,
            "invalid_format",
            "Please enter a valid HTTP or HTTPS URL."
        )

    try:
        parsed = urlparse(
            url
        )
    except ValueError:
        return _set_result(
            False,
            "invalid_format",
            "Please enter a valid HTTP or HTTPS URL."
        )

    scheme = (
        parsed.scheme
        or ""
    ).lower()

    if scheme not in ALLOWED_SCHEMES:
        return _set_result(
            False,
            "invalid_scheme",
            "Please enter a valid HTTP or HTTPS URL."
        )

    if not parsed.netloc:
        return _set_result(
            False,
            "invalid_format",
            "Please enter a valid HTTP or HTTPS URL."
        )

    try:
        hostname = _normalize_hostname(
            parsed.hostname
        )
    except ValueError:
        hostname = None

    if not hostname:
        return _set_result(
            False,
            "invalid_format",
            "Please enter a valid HTTP or HTTPS URL."
        )

    if (
        parsed.username is not None
        or parsed.password is not None
    ):
        return _set_result(
            False,
            "embedded_credentials",
            (
                "URLs containing embedded usernames "
                "or passwords cannot be scanned."
            ),
            hostname
        )

    try:
        parsed_port = parsed.port
    except ValueError:
        return _set_result(
            False,
            "invalid_port",
            "The URL contains an invalid port number.",
            hostname
        )

    port = parsed_port

    if port is None:
        port = (
            443
            if scheme == "https"
            else 80
        )

    if not (
        1 <= port <= 65535
    ):
        return _set_result(
            False,
            "invalid_port",
            "The URL contains an invalid port number.",
            hostname
        )

    if _hostname_is_blocked(
        hostname
    ):
        return _set_result(
            False,
            "private_target",
            (
                "Private or local network addresses "
                "cannot be scanned. Please enter a valid "
                "public HTTP or HTTPS URL."
            ),
            hostname
        )

    literal_ip_result = (
        _validate_literal_ip(
            hostname
        )
    )

    if literal_ip_result is not None:
        if literal_ip_result:
            return _set_result(
                True,
                "valid",
                "URL is valid.",
                hostname
            )

        return _set_result(
            False,
            "private_target",
            (
                "Private or local network addresses "
                "cannot be scanned. Please enter a valid "
                "public HTTP or HTTPS URL."
            ),
            hostname
        )

    if not _hostname_syntax_valid(
        hostname
    ):
        return _set_result(
            False,
            "invalid_domain",
            "Please enter a valid HTTP or HTTPS URL.",
            hostname
        )

    resolved_ips = _resolve_hostname(
        hostname,
        port
    )

    if not resolved_ips:
        return _set_result(
            False,
            "dns_failed",
            (
                "The domain could not be resolved. "
                "It may be offline or unavailable."
            ),
            hostname
        )

    if not all(
        _is_public_ip(ip_value)
        for ip_value in resolved_ips
    ):
        return _set_result(
            False,
            "private_target",
            (
                "Private or local network addresses "
                "cannot be scanned. Please enter a valid "
                "public HTTP or HTTPS URL."
            ),
            hostname
        )

    return _set_result(
        True,
        "valid",
        "URL is valid.",
        hostname
    )