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


def get_domain_name(hostname):
    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    suffix = ".".join(parts[-2:])

    if suffix in MULTI_LEVEL_TLDS:
        if len(parts) >= 3:
            return parts[-3]

        return ""

    return parts[-2]


def check_hyphen(url):
    try:
        hostname = urlparse(url).hostname

        if not hostname:
            return (
                0,
                "Not Checked",
                0
            )

        hostname = hostname.lower().rstrip(".")

        if hostname.startswith("www."):
            hostname = hostname[4:]

        domain_name = get_domain_name(
            hostname
        )

        if not domain_name:
            return (
                0,
                "Not Checked",
                0
            )

        # Punycode encoding uses hyphens internally.
        if domain_name.startswith("xn--"):
            return (
                0,
                "🟢 Hyphen Check Skipped for Punycode",
                0
            )

        hyphen_count = domain_name.count("-")

        if hyphen_count == 0:
            return (
                0,
                "✅ No Hyphens",
                0
            )

        if hyphen_count == 1:
            return (
                1,
                "🟡 One Hyphen",
                5
            )

        if hyphen_count <= 3:
            return (
                hyphen_count,
                "⚠️ Multiple Hyphens",
                15
            )

        return (
            hyphen_count,
            "🚨 Excessive Hyphens",
            25
        )

    except Exception:
        return (
            0,
            "Not Checked",
            0
        )