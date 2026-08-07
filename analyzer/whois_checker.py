from urllib.parse import urlparse
import whois


def extract_domain(url):

    try:

        hostname = urlparse(url).hostname

        if not hostname:

            return None

        hostname = hostname.lower()

        if hostname.startswith("www."):

            hostname = hostname[4:]

        return hostname

    except Exception:

        return None


def format_date(value):

    try:

        if isinstance(value, list):

            value = value[0]

        if value is None:

            return "Unknown"

        return value.strftime("%d-%m-%Y")

    except Exception:

        return "Unknown"


def format_list(value):

    try:

        if isinstance(value, list):

            unique = sorted(set(str(item) for item in value))

            return ", ".join(unique)

        if value:

            return str(value)

        return "Unknown"

    except Exception:

        return "Unknown"


def get_whois_info(url):

    """
    Returns

    {

        registrar,
        creation_date,
        expiration_date,
        updated_date,
        organization,
        country,
        status,
        name_servers

    }

    """

    try:

        domain = extract_domain(url)

        if not domain:

            return {

                "registrar": "Unknown",
                "creation_date": "Unknown",
                "expiration_date": "Unknown",
                "updated_date": "Unknown",
                "organization": "Unknown",
                "country": "Unknown",
                "status": "Unknown",
                "name_servers": "Unknown"

            }

        data = whois.whois(domain)

        return {

            "registrar":

            data.registrar or "Unknown",

            "creation_date":

            format_date(data.creation_date),

            "expiration_date":

            format_date(data.expiration_date),

            "updated_date":

            format_date(data.updated_date),

            "organization":

            getattr(data, "org", None)

            or getattr(data, "organization", None)

            or "Unknown",

            "country":

            getattr(data, "country", None)

            or "Unknown",

            "status":

            format_list(

                getattr(data, "status", None)

            ),

            "name_servers":

            format_list(

                data.name_servers

            )

        }

    except Exception:

        return {

            "registrar": "Unknown",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "updated_date": "Unknown",
            "organization": "Unknown",
            "country": "Unknown",
            "status": "Unknown",
            "name_servers": "Unknown"

        }