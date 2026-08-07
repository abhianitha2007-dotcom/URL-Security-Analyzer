import xml.etree.ElementTree as ET

from urllib.parse import urljoin, urlparse

import requests
from analyzer.safe_http import safe_requests


MAX_SITEMAP_FILES = 10
MAX_URLS_PER_SITEMAP = 5000
MAX_TOTAL_URLS = 10000


SENSITIVE_SEGMENTS = {
    "admin",
    "administrator",
    "backup",
    "backups",
    "private",
    "secret",
    "secrets",
    "config",
    "database",
    "db",
    "phpmyadmin",
    "internal",
    "staging",
    "development",
    "dev",
    "debug",
    "logs",
    "temp",
    "tmp"
}


ATTENTION_SEGMENTS = {
    "login",
    "signin",
    "account",
    "auth",
    "api",
    "test",
    "old",
    "beta"
}


SENSITIVE_FILES = {
    ".env",
    ".git",
    "backup.zip",
    "backup.sql",
    "database.sql",
    "config.php",
    "phpinfo.php",
    "debug.log"
}


def build_default_sitemap_url(url):
    """
    Builds the default /sitemap.xml URL.
    """

    try:
        parsed = urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            return None

        base_url = (
            f"{parsed.scheme}://{parsed.netloc}"
        )

        return urljoin(
            base_url,
            "/sitemap.xml"
        )

    except Exception:
        return None


def normalize_url(value):
    """
    Removes surrounding spaces from a URL.
    """

    if not value:
        return ""

    return value.strip()


def extract_path_segments(url):
    """
    Extracts normalized URL path segments.
    """

    try:
        path = urlparse(url).path.lower()

        return [
            segment
            for segment in path.split("/")
            if segment
        ]

    except Exception:
        return []


def classify_url(url):
    """
    Classifies a sitemap URL.

    Returns:
        level,
        reason
    """

    lower_url = url.lower()
    segments = extract_path_segments(url)

    for sensitive_file in SENSITIVE_FILES:
        if sensitive_file in lower_url:
            return (
                "high",
                f"Sensitive file reference: {sensitive_file}"
            )

    for segment in segments:
        if segment in SENSITIVE_SEGMENTS:
            return (
                "high",
                f"Sensitive path segment: {segment}"
            )

    for segment in segments:
        if segment in ATTENTION_SEGMENTS:
            return (
                "attention",
                f"Attention path segment: {segment}"
            )

    return (
        "normal",
        ""
    )


def parse_sitemap_xml(content):
    """
    Parses either:

    - sitemap index
    - regular URL sitemap

    Returns:
        sitemap_urls,
        page_urls
    """

    sitemap_urls = []
    page_urls = []

    try:
        root = ET.fromstring(content)

    except ET.ParseError:
        return (
            sitemap_urls,
            page_urls
        )

    root_name = root.tag.split("}")[-1].lower()

    for element in root.iter():
        element_name = (
            element.tag
            .split("}")[-1]
            .lower()
        )

        if element_name != "loc":
            continue

        value = normalize_url(
            element.text
        )

        if not value:
            continue

        if root_name == "sitemapindex":
            sitemap_urls.append(value)

        elif root_name == "urlset":
            page_urls.append(value)

    return (
        sitemap_urls,
        page_urls
    )


def fetch_sitemap(url):
    """
    Downloads one sitemap file.

    Returns:
        response text,
        status code,
        final URL
    """

    try:
        response = safe_requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(compatible; URLSecurityAnalyzer/2.0)"
                )
            }
        )

        if response.status_code != 200:
            return (
                None,
                response.status_code,
                response.url
            )

        content = response.content[
            :5_000_000
        ]

        return (
            content,
            response.status_code,
            response.url
        )

    except requests.RequestException:
        return (
            None,
            None,
            url
        )


def check_sitemap(
    url,
    discovered_sitemaps=None
):
    """
    Analyzes sitemap.xml files.

    Returns:
        {
            found,
            status,
            score,
            sitemap_files,
            url_count,
            suspicious_urls,
            attention_urls,
            errors
        }
    """

    result = {
        "found": False,
        "status": "Not Checked",
        "score": 0,
        "sitemap_files": [],
        "url_count": 0,
        "suspicious_urls": [],
        "attention_urls": [],
        "errors": []
    }

    default_sitemap = build_default_sitemap_url(
        url
    )

    if not default_sitemap:
        result["status"] = "Invalid URL"
        return result

    queue = []

    if discovered_sitemaps:
        for sitemap_url in discovered_sitemaps:
            normalized = normalize_url(
                sitemap_url
            )

            if normalized:
                queue.append(normalized)

    if default_sitemap not in queue:
        queue.append(default_sitemap)

    visited = set()
    all_page_urls = []
    suspicious_urls = []
    attention_urls = []

    while (
        queue
        and len(visited) < MAX_SITEMAP_FILES
        and len(all_page_urls) < MAX_TOTAL_URLS
    ):
        sitemap_url = queue.pop(0)

        if sitemap_url in visited:
            continue

        visited.add(sitemap_url)

        content, status_code, final_url = (
            fetch_sitemap(sitemap_url)
        )

        if content is None:
            if status_code not in (404, 410):
              result["errors"].append(
        {
            "url": sitemap_url,
            "status_code": status_code
        }
    )
            continue

        result["found"] = True

        if final_url not in result["sitemap_files"]:
         result["sitemap_files"].append(
        final_url
    )

        (
            nested_sitemaps,
            page_urls
        ) = parse_sitemap_xml(content)

        for nested_url in nested_sitemaps:
            if (
                nested_url not in visited
                and nested_url not in queue
                and len(queue) < MAX_SITEMAP_FILES
            ):
                queue.append(nested_url)

        for page_url in page_urls[
            :MAX_URLS_PER_SITEMAP
        ]:
            if len(all_page_urls) >= MAX_TOTAL_URLS:
                break

            if page_url in all_page_urls:
                continue

            all_page_urls.append(page_url)

            level, reason = classify_url(
                page_url
            )

            entry = {
                "url": page_url,
                "reason": reason
            }

            if level == "high":
                suspicious_urls.append(entry)

            elif level == "attention":
                attention_urls.append(entry)

    result["url_count"] = len(
        all_page_urls
    )

    result["suspicious_urls"] = (
        suspicious_urls[:25]
    )

    result["attention_urls"] = (
        attention_urls[:25]
    )

    suspicious_count = len(
        suspicious_urls
    )

    attention_count = len(
        attention_urls
    )

    if not result["found"]:
        result["status"] = (
            "🟢 Sitemap Not Found"
        )
        return result

    if suspicious_count >= 5:
        result["status"] = (
            "🔴 Multiple Sensitive URLs Listed"
        )
        result["score"] = 6

    elif suspicious_count > 0:
        result["status"] = (
            "🟠 Sensitive URLs Listed"
        )
        result["score"] = 4

    elif attention_count >= 10:
        result["status"] = (
            "🟡 Many Login, API or Test URLs Listed"
        )
        result["score"] = 2

    elif attention_count > 0:
        result["status"] = (
            "🟢 Sitemap Found — "
            "Informational URLs Detected"
        )
        result["score"] = 0

    else:
        result["status"] = (
            "🟢 Sitemap Found — "
            "No Sensitive URLs Detected"
        )
        result["score"] = 0

    return result