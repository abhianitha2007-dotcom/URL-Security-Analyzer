import whois
from datetime import datetime


def check_domain_age(url):
    try:
        # Extract domain
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]

        # Fetch WHOIS information
        w = whois.whois(domain)

        creation = w.creation_date

        # Some WHOIS servers return a list
        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            return {
                "age": "Unknown",
                "risk": True,
                "message": "Could not determine domain age."
            }

        # Remove timezone information if present
        if hasattr(creation, "tzinfo") and creation.tzinfo is not None:
            creation = creation.replace(tzinfo=None)

        age_days = (datetime.now() - creation).days

        if age_days < 180:
            return {
                "age": f"{age_days} days",
                "risk": True,
                "message": "⚠️ Very new domain."
            }

        elif age_days < 365:
            return {
                "age": f"{age_days} days",
                "risk": True,
                "message": "⚠️ Domain is less than one year old."
            }

        else:
            return {
                "age": f"{age_days} days",
                "risk": False,
                "message": "✅ Old domain."
            }

    except Exception:
        return {
            "age": "Unknown",
            "risk": True,
            "message": "WHOIS lookup failed."
        }