"""Detect compact cross-site redirects without a provider allowlist."""

import re
from urllib.parse import urlparse


def _host(value):
    return (urlparse(value).hostname or "").lower().removeprefix("www.")


def check_shortener(url, response=None):
    """Return an informational compact-link signal from the captured redirect."""
    try:
        if response is None or not response.history:
            return False, "No compact cross-site redirect detected", 0

        original = urlparse(url)
        original_host = _host(url)
        final_host = _host(response.url)
        cross_site = bool(
            original_host
            and final_host
            and original_host != final_host
            and not original_host.endswith("." + final_host)
            and not final_host.endswith("." + original_host)
        )
        path_token = original.path.strip("/").split("/", 1)[0]
        compact_token = bool(re.fullmatch(r"[A-Za-z0-9_-]{2,16}", path_token))

        if cross_site and compact_token:
            return True, "Compact cross-site redirect observed", 0
        if cross_site:
            return False, "Cross-site redirect observed", 0
        return False, "No compact cross-site redirect detected", 0
    except (TypeError, ValueError):
        return False, "Not checked", 0
