import dns.resolver

from urllib.parse import urlparse


DNS_RECORD_TYPES = [

    "A",
    "AAAA",
    "MX",
    "NS",
    "CNAME",
    "TXT"

]


def get_hostname(url):

    try:

        hostname = urlparse(url).hostname

        if hostname:

            return hostname.lower()

        return None

    except Exception:

        return None


def get_dns_records(url):

    """
    Returns

    {

        A: [],
        AAAA: [],
        MX: [],
        NS: [],
        CNAME: [],
        TXT: []

    }

    """

    records = {

        record_type: []

        for record_type in DNS_RECORD_TYPES

    }

    try:

        hostname = get_hostname(url)

        if not hostname:

            return records

        resolver = dns.resolver.Resolver()

        resolver.timeout = 3

        resolver.lifetime = 5

        for record_type in DNS_RECORD_TYPES:

            try:

                answers = resolver.resolve(

                    hostname,

                    record_type

                )

                for answer in answers:

                    value = str(answer).strip()

                    if value not in records[record_type]:

                        records[record_type].append(value)

            except (

                dns.resolver.NoAnswer,

                dns.resolver.NXDOMAIN,

                dns.resolver.NoNameservers,

                dns.resolver.Timeout

            ):

                continue

            except Exception:

                continue

        return records

    except Exception:

        return records