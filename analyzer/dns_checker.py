import dns.resolver
from urllib.parse import urlparse


def get_dns_records(url):
    """
    Retrieves common DNS records.

    Returns:
        dict
    """

    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return {}

        records = {}

        dns_types = [
            "A",
            "AAAA",
            "MX",
            "NS",
            "CNAME"
        ]

        for record_type in dns_types:

            try:

                answers = dns.resolver.resolve(
                    hostname,
                    record_type
                )

                values = []

                for answer in answers:
                    values.append(str(answer))

                records[record_type] = values

            except Exception:

                records[record_type] = []

        return records

    except Exception:

        return {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "CNAME": []
        }