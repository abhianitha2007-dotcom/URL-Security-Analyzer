from urllib.parse import urlparse


def count_subdomains(url):
    """
    Counts the number of subdomains.

    Returns:
        subdomain_count
        status
        score
    """

    hostname = urlparse(url).hostname

    if not hostname:
        return 0, "Not Checked", 0

    hostname = hostname.lower()

    # Ignore common www prefix
    if hostname.startswith("www."):
        hostname = hostname[4:]

    parts = hostname.split(".")

    # Domain + TLD are not subdomains
    subdomain_count = max(0, len(parts) - 2)

    if subdomain_count == 0:
        return subdomain_count, "🟢 Normal", 0

    elif subdomain_count == 1:
        return subdomain_count, "🟢 One Subdomain", 5

    elif subdomain_count == 2:
        return subdomain_count, "🟡 Multiple Subdomains", 15

    else:
        return subdomain_count, "🔴 Too Many Subdomains", 30