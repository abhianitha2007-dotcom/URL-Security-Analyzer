"""Report a URL's domain suffix without assigning reputation by TLD."""

from urllib.parse import urlparse


def check_tld(url):
    try:
        hostname = (urlparse(url).hostname or "").rstrip(".").lower()
        labels = hostname.split(".")
        if len(labels) < 2 or not labels[-1]:
            return "Unknown", "Invalid domain suffix", 0

        suffix = labels[-1]
        return suffix, f"Domain suffix observed (.{suffix})", 0
    except (TypeError, ValueError):
        return "Unknown", "Not checked", 0
