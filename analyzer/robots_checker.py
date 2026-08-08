import re

from urllib.parse import urljoin, urlparse

import requests

from analyzer.safe_http import safe_requests


SENSITIVE_SEGMENTS = {
    "admin",
    "administrator",
    "backup",
    "backups",
    "private",
    "dev",
    "development",
    "staging",
    "config",
    "database",
    "db",
    "secret",
    "secrets",
    "logs",
    "log",
    "tmp",
    "temp",
    "phpmyadmin",
    "internal"
}


SENSITIVE_FILES = {
    ".env",
    ".git",
    "config.php",
    "database.sql",
    "backup.zip",
    "backup.sql",
    "debug.log",
    "phpinfo.php"
}


def build_robots_url(url):
    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return None

    base_url = (
        f"{parsed.scheme}://{parsed.netloc}"
    )

    return urljoin(
        base_url,
        "/robots.txt"
    )


def extract_path_segments(path):
    return [
        segment.lower()
        for segment in re.split(
            r"[/\\]+",
            path
        )
        if segment
    ]


def is_sensitive_path(path):
    lower_path = (
        path
        .lower()
        .strip()
    )

    if not lower_path:
        return False

    segments = extract_path_segments(
        lower_path
    )

    for segment in segments:
        clean_segment = (
            segment.strip()
        )

        if clean_segment in SENSITIVE_SEGMENTS:
            return True

        if clean_segment in SENSITIVE_FILES:
            return True

    for sensitive_file in SENSITIVE_FILES:
        if lower_path.endswith(
            "/" + sensitive_file
        ):
            return True

        if lower_path == sensitive_file:
            return True

    return False


def parse_robots_content(content):
    disallowed_paths = []
    suspicious_paths = []
    sitemap_urls = []

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        line_without_comment = line.split(
            "#",
            1
        )[0].strip()

        if not line_without_comment:
            continue

        if ":" not in line_without_comment:
            continue

        directive, value = (
            line_without_comment.split(
                ":",
                1
            )
        )

        directive = (
            directive
            .strip()
            .lower()
        )

        value = value.strip()

        if not value:
            continue

        if directive == "disallow":
            disallowed_paths.append(
                value
            )

            if is_sensitive_path(
                value
            ):
                suspicious_paths.append(
                    value
                )

        elif directive == "sitemap":
            sitemap_urls.append(
                value
            )

    return (
        sorted(
            set(disallowed_paths)
        ),
        sorted(
            set(suspicious_paths)
        ),
        sorted(
            set(sitemap_urls)
        )
    )


def http_status_message(status_code):
    if status_code in {
        401,
        403
    }:
        return (
            "⚪ robots.txt Access Restricted"
        )

    if status_code == 429:
        return (
            "⚪ Could not verify robots.txt — "
            "request was rate limited"
        )

    if 500 <= status_code <= 599:
        return (
            "⚪ Could not verify robots.txt — "
            "website temporarily unavailable"
        )

    if 400 <= status_code <= 499:
        return (
            "⚪ Could not verify robots.txt"
        )

    return (
        "⚪ Could not verify robots.txt — "
        "unexpected server response"
    )


def check_robots(url):
    result = {
        "found": False,
        "url": None,
        "status_code": None,
        "status": (
            "Could not verify robots.txt"
        ),
        "score": 0,
        "disallow_count": 0,
        "suspicious_paths": [],
        "sitemap_urls": []
    }

    try:
        robots_url = build_robots_url(
            url
        )

        if not robots_url:
            result["status"] = (
                "Invalid URL"
            )

            return result

        result["url"] = robots_url

        response = safe_requests.get(
            robots_url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(compatible; "
                    "URLSecurityAnalyzer/2.0)"
                )
            }
        )

        result["status_code"] = (
            response.status_code
        )

        if response.status_code == 404:
            result["status"] = (
                "🟢 No robots.txt Found"
            )

            return result

        if response.status_code != 200:
            result["status"] = (
                http_status_message(
                    response.status_code
                )
            )

            return result

        content_type = (
            response.headers.get(
                "Content-Type",
                ""
            )
            .lower()
        )

        text = response.text[
            :1_000_000
        ]

        if (
            "text/html" in content_type
            and "<html" in text.lower()
        ):
            result["status"] = (
                "⚪ Could not verify robots.txt — "
                "unexpected webpage response"
            )

            return result

        result["found"] = True

        (
            disallowed_paths,
            suspicious_paths,
            sitemap_urls
        ) = parse_robots_content(
            text
        )

        result["disallow_count"] = len(
            disallowed_paths
        )

        result["suspicious_paths"] = (
            suspicious_paths
        )

        result["sitemap_urls"] = (
            sitemap_urls
        )

        suspicious_count = len(
            suspicious_paths
        )

        if suspicious_count == 0:
            result["status"] = (
                "🟢 robots.txt Found — "
                "No Sensitive Paths Detected"
            )

            result["score"] = 0

        elif suspicious_count <= 2:
            result["status"] = (
                "🟡 Sensitive Paths Listed"
            )

            result["score"] = 2

        elif suspicious_count <= 5:
            result["status"] = (
                "🟠 Multiple Sensitive Paths Listed"
            )

            result["score"] = 4

        else:
            result["status"] = (
                "🔴 Many Sensitive Paths Listed"
            )

            result["score"] = 6

        return result

    except requests.Timeout:
        result["status"] = (
            "⚪ Could not verify robots.txt — "
            "website did not respond"
        )

        return result

    except requests.RequestException:
        result["status"] = (
            "⚪ Could not verify robots.txt — "
            "website unavailable"
        )

        return result

    except Exception:
        result["status"] = (
            "⚪ Could not verify robots.txt"
        )

        return result