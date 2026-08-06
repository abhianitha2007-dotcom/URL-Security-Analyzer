from urllib.parse import urlparse


STANDARD_PORTS = {
    "http": 80,
    "https": 443
}


HIGH_RISK_PORTS = {
    21,
    22,
    23,
    25,
    53,
    110,
    135,
    139,
    445,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    8081,
    9200,
    27017
}


COMMON_ALTERNATIVE_PORTS = {
    8000,
    8008,
    8080,
    8443,
    8888
}


def check_port(url):
    """
    Checks whether the URL uses a non-standard port.

    Returns:
        port,
        status,
        score
    """

    try:
        parsed = urlparse(url)

        if not parsed.hostname:
            return (
                None,
                "Not Checked",
                0
            )

        try:
            port = parsed.port
        except ValueError:
            return (
                None,
                "🔴 Invalid Port",
                20
            )

        if port is None:
            default_port = STANDARD_PORTS.get(parsed.scheme.lower())

            return (
                default_port,
                "🟢 Default Port",
                0
            )

        expected_port = STANDARD_PORTS.get(parsed.scheme.lower())

        if expected_port and port == expected_port:
            return (
                port,
                "🟢 Standard Port",
                0
            )

        if port in HIGH_RISK_PORTS:
            return (
                port,
                f"🔴 High-Risk Port ({port})",
                20
            )

        if port in COMMON_ALTERNATIVE_PORTS:
            return (
                port,
                f"🟡 Alternative Web Port ({port})",
                8
            )

        if port < 1 or port > 65535:
            return (
                port,
                "🔴 Invalid Port Range",
                20
            )

        return (
            port,
            f"🟠 Non-Standard Port ({port})",
            12
        )

    except Exception:
        return (
            None,
            "Not Checked",
            0
        )