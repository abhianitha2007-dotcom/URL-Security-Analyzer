from urllib.parse import urlparse


def check_hyphen(url):
    """
    Detects excessive hyphens in the domain.

    Returns:
        hyphen_count
        status
        score
    """

    hostname = urlparse(url).hostname

    if hostname is None:
        return 0, "Not Checked", 0

    hyphen_count = hostname.count("-")

    if hyphen_count == 0:
        return hyphen_count, "✅ No Hyphens", 0

    elif hyphen_count == 1:
        return hyphen_count, "🟡 One Hyphen", 10

    elif hyphen_count <= 3:
        return hyphen_count, "⚠️ Multiple Hyphens", 20

    else:
        return hyphen_count, "🚨 Excessive Hyphens", 30