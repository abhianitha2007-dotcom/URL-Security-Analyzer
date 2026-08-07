from urllib.parse import urljoin, urlparse

import requests
from analyzer.safe_http import safe_requests
from bs4 import BeautifulSoup


def get_hostname(url):

    try:
        hostname = urlparse(url).hostname
        return hostname.lower() if hostname else ""

    except Exception:
        return ""


def check_favicon(url):

    """
    Returns:
        favicon_url,
        status,
        score
    """

    try:
        response = safe_requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        content_type = response.headers.get(
            "Content-Type",
            ""
        ).lower()

        if "text/html" not in content_type:
            return (
                None,
                "Not Checked",
                0
            )

        soup = BeautifulSoup(
            response.text[:1_000_000],
            "html.parser"
        )

        favicon = soup.find(
            "link",
            rel=lambda value: (
                value
                and "icon" in " ".join(value)
                if isinstance(value, list)
                else value
                and "icon" in value.lower()
            )
        )

        if favicon is None:
            return (
                None,
                "🟢 No Favicon Declared",
                0
            )

        href = favicon.get("href", "").strip()

        if not href:
            return (
                None,
                "🟢 No Favicon URL",
                0
            )

        if href.startswith("data:"):
            return (
                href,
                "🟢 Embedded Favicon",
                0
            )

        favicon_url = urljoin(
            response.url,
            href
        )

        page_host = get_hostname(response.url)
        favicon_host = get_hostname(favicon_url)

        if not favicon_host:
            return (
                favicon_url,
                "🟢 Embedded or Local Favicon",
                0
            )

        if favicon_host == page_host:
            return (
                favicon_url,
                "🟢 Local Favicon",
                0
            )

        if favicon_host.endswith("." + page_host):
            return (
                favicon_url,
                "🟢 Same-Domain Favicon",
                0
            )

        return (
            favicon_url,
            "🟢 External Favicon or CDN Asset",
            0
        )

    except requests.RequestException:
        return (
            None,
            "Not Checked",
            0
        )

    except Exception:
        return (
            None,
            "Not Checked",
            0
        )