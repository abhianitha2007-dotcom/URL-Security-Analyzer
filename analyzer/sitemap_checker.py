import xml.etree.ElementTree as ET

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests

from analyzer.safe_http import safe_requests


MAX_SITEMAP_FILES = 10
MAX_URLS_PER_SITEMAP = 5000
MAX_TOTAL_URLS = 10000
MAX_WORKERS = 4


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
    if not value:
        return ""

    return value.strip()


def extract_path_segments(url):
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
    sitemap_urls = []
    page_urls = []

    try:
        root = ET.fromstring(content)

    except ET.ParseError:
        return (
            sitemap_urls,
            page_urls
        )

    root_name = (
        root.tag
        .split("}")[-1]
        .lower()
    )

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
            sitemap_urls.append(
                value
            )

        elif root_name == "urlset":
            page_urls.append(
                value
            )

    return (
        sitemap_urls,
        page_urls
    )


def fetch_sitemap(url):
    try:
        response = safe_requests.get(
            url,
            timeout=(3, 6),
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

    default_sitemap = (
        build_default_sitemap_url(
            url
        )
    )

    if not default_sitemap:
        result["status"] = "Invalid URL"
        return result

    queue = []
    queued = set()

    if discovered_sitemaps:
        for sitemap_url in discovered_sitemaps:

            normalized = normalize_url(
                sitemap_url
            )

            if (
                normalized
                and normalized not in queued
            ):
                queue.append(
                    normalized
                )

                queued.add(
                    normalized
                )

    if default_sitemap not in queued:
        queue.append(
            default_sitemap
        )

        queued.add(
            default_sitemap
        )

    visited = set()

    page_seen = set()
    all_page_urls = []

    suspicious_urls = []
    attention_urls = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        while (
            queue
            and len(visited) < MAX_SITEMAP_FILES
            and len(all_page_urls) < MAX_TOTAL_URLS
        ):

            remaining = (
                MAX_SITEMAP_FILES
                - len(visited)
            )

            batch_size = min(
                MAX_WORKERS,
                remaining,
                len(queue)
            )

            batch = []

            while (
                queue
                and len(batch) < batch_size
            ):

                sitemap_url = queue.pop(0)

                if sitemap_url in visited:
                    continue

                visited.add(
                    sitemap_url
                )

                batch.append(
                    sitemap_url
                )

            if not batch:
                continue

            responses = list(
                executor.map(
                    fetch_sitemap,
                    batch
                )
            )

            for (
                sitemap_url,
                response_data
            ) in zip(
                batch,
                responses
            ):

                (
                    content,
                    status_code,
                    final_url
                ) = response_data

                if content is None:

                    if status_code not in (
                        404,
                        410
                    ):
                        result["errors"].append(
                            {
                                "url":
                                    sitemap_url,

                                "status_code":
                                    status_code
                            }
                        )

                    continue

                result["found"] = True

                if (
                    final_url
                    not in result["sitemap_files"]
                ):
                    result[
                        "sitemap_files"
                    ].append(
                        final_url
                    )

                (
                    nested_sitemaps,
                    page_urls
                ) = parse_sitemap_xml(
                    content
                )

                for nested_url in nested_sitemaps:

                    normalized = normalize_url(
                        nested_url
                    )

                    if not normalized:
                        continue

                    if (
                        normalized in visited
                        or normalized in queued
                    ):
                        continue

                    if (
                        len(visited)
                        + len(queue)
                        >= MAX_SITEMAP_FILES
                    ):
                        break

                    queue.append(
                        normalized
                    )

                    queued.add(
                        normalized
                    )

                for page_url in page_urls[
                    :MAX_URLS_PER_SITEMAP
                ]:

                    if (
                        len(all_page_urls)
                        >= MAX_TOTAL_URLS
                    ):
                        break

                    if page_url in page_seen:
                        continue

                    page_seen.add(
                        page_url
                    )

                    all_page_urls.append(
                        page_url
                    )

                    (
                        level,
                        reason
                    ) = classify_url(
                        page_url
                    )

                    entry = {
                        "url":
                            page_url,

                        "reason":
                            reason
                    }

                    if level == "high":
                        suspicious_urls.append(
                            entry
                        )

                    elif level == "attention":
                        attention_urls.append(
                            entry
                        )

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

    else:

        result["status"] = (
            "🟢 Sitemap Found — "
            "No Sensitive URLs Detected"
        )

    return result