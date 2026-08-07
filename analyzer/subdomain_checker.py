from urllib.parse import urlparse


MULTI_LEVEL_TLDS = {

    "co.uk",
    "org.uk",
    "gov.uk",

    "co.in",
    "gov.in",
    "nic.in",
    "ac.in",
    "edu.in",
    "net.in",
    "firm.in",

    "com.au",
    "net.au",

    "co.jp"

}


TRUSTED_SUBDOMAINS = {

    "www",
    "mail",
    "docs",
    "drive",
    "accounts",
    "account",
    "support",
    "help",
    "api",
    "cdn",
    "images",
    "img",
    "static",
    "assets",
    "ftp",
    "blog",
    "news",
    "portal",
    "login"

}


def get_domain_parts(hostname):

    parts = hostname.split(".")

    if len(parts) < 2:

        return parts

    last_two = ".".join(parts[-2:])

    if last_two in MULTI_LEVEL_TLDS:

        return parts[:-2]

    return parts[:-1]


def count_subdomains(url):

    """
    Returns

        count,
        status,
        score
    """

    try:

        hostname = urlparse(url).hostname

        if not hostname:

            return (

                0,

                "Not Checked",

                0

            )

        hostname = hostname.lower()

        if hostname.startswith("www."):

            hostname = hostname[4:]

        domain_parts = get_domain_parts(hostname)

        subdomains = domain_parts[:-1]

        count = len(subdomains)

        if count == 0:

            return (

                0,

                "🟢 No Subdomain",

                0

            )

        if count == 1:

            if subdomains[0] in TRUSTED_SUBDOMAINS:

                return (

                    1,

                    "🟢 Trusted Subdomain",

                    0

                )

            return (

                1,

                "🟢 One Subdomain",

                2

            )

        if count == 2:

            return (

                2,

                "🟢 Two Subdomains",

                2

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