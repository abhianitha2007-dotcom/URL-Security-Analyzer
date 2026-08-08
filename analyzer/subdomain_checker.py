from urllib.parse import urlparse


MULTI_LEVEL_TLDS = {
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",

    "co.in",
    "com.in",
    "org.in",
    "net.in",
    "gov.in",
    "nic.in",
    "ac.in",
    "edu.in",
    "res.in",
    "firm.in",
    "gen.in",
    "ind.in",
    "mil.in",

    "com.au",
    "net.au",
    "org.au",

    "co.jp",
    "ne.jp",
    "or.jp"
}


def get_domain_parts(hostname):
    parts = hostname.split(".")

    if len(parts) < 2:
        return parts

    last_two = ".".join(
        parts[-2:]
    )

    if last_two in MULTI_LEVEL_TLDS:
        return parts[:-2]

    return parts[:-1]


def count_subdomains(url):
    try:
        hostname = urlparse(
            url
        ).hostname

        if not hostname:
            return (
                0,
                "Not Checked",
                0
            )

        hostname = (
            hostname
            .lower()
            .rstrip(".")
        )

        if hostname.startswith("www."):
            hostname = hostname[4:]

        domain_parts = get_domain_parts(
            hostname
        )

        subdomains = domain_parts[:-1]

        count = len(
            subdomains
        )

        if count == 0:
            return (
                0,
                "🟢 No Subdomain",
                0
            )

        if count == 1:
            return (
                1,
                "🟢 One Subdomain",
                0
            )

        if count == 2:
            return (
                2,
                "🟢 Two Subdomains",
                0
            )

        if count == 3:
            return (
                3,
                "🟡 Multiple Subdomains",
                6
            )

        return (
            count,
            "🔴 Excessive Subdomains",
            18
        )

    except Exception:
        return (
            0,
            "Not Checked",
            0
        )