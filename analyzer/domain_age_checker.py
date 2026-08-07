from datetime import datetime
from urllib.parse import urlparse

import whois


def extract_domain(url):

    hostname = urlparse(url).hostname

    if not hostname:
        return None

    hostname = hostname.lower()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname


def get_creation_date(value):

    if isinstance(value, list):
        value = value[0]

    if not isinstance(value, datetime):
        return None

    if value.tzinfo:
        value = value.replace(tzinfo=None)

    return value


def unknown_result(message):

    return {
        "age": "Unknown",
        "risk": False,
        "confirmed_new": False,
        "message": message
    }


def check_domain_age(url):

    """
    Returns:
        {
            age,
            risk,
            confirmed_new,
            message
        }
    """

    try:
        domain = extract_domain(url)

        if not domain:
            return unknown_result(
                "Invalid domain."
            )

        data = whois.whois(domain)

        creation_date = get_creation_date(
            data.creation_date
        )

        if not creation_date:
            return unknown_result(
                "Domain age could not be verified."
            )

        age_days = (
            datetime.now() - creation_date
        ).days

        age_years = round(
            age_days / 365.25,
            1
        )

        if age_days < 30:
            return {
                "age": f"{age_days} days",
                "risk": True,
                "confirmed_new": True,
                "message": (
                    "🔴 Domain registered within "
                    "the last 30 days."
                )
            }

        if age_days < 180:
            return {
                "age": f"{age_days} days",
                "risk": True,
                "confirmed_new": True,
                "message": "🟠 Very new domain."
            }

        if age_days < 365:
            return {
                "age": f"{age_days} days",
                "risk": True,
                "confirmed_new": True,
                "message": (
                    "🟡 Domain is less than "
                    "one year old."
                )
            }

        if age_days < 1095:
            return {
                "age": f"{age_years} years",
                "risk": False,
                "confirmed_new": False,
                "message": "🟢 Established domain."
            }

        return {
            "age": f"{age_years} years",
            "risk": False,
            "confirmed_new": False,
            "message": "✅ Well-established domain."
        }

    except Exception:
        return unknown_result(
            "WHOIS lookup failed."
        )