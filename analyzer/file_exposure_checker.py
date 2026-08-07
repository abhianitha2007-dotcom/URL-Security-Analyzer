from urllib.parse import urljoin, urlparse

import requests
from analyzer.safe_http import safe_requests


CHECK_PATHS = {
    ".env": {
        "path": "/.env",
        "severity": 10
    },

    "git_head": {
        "path": "/.git/HEAD",
        "severity": 10
    },

    "phpinfo": {
        "path": "/phpinfo.php",
        "severity": 6
    },

    "backup_zip": {
        "path": "/backup.zip",
        "severity": 8
    },

    "database_sql": {
        "path": "/database.sql",
        "severity": 10
    },

    "config_php": {
        "path": "/config.php",
        "severity": 6
    }
}


ENV_MARKERS = {
    "DB_PASSWORD",
    "DB_USERNAME",
    "DATABASE_URL",
    "APP_KEY",
    "SECRET_KEY",
    "AWS_ACCESS_KEY_ID"
}


GIT_HEAD_MARKERS = {
    "ref: refs/heads/",
    "ref: refs/remotes/"
}


PHPINFO_MARKERS = {
    "PHP Version",
    "phpinfo()",
    "PHP Credits"
}


def build_base_url(url):
    try:
        parsed = urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            return None

        return (
            f"{parsed.scheme}://{parsed.netloc}"
        )

    except Exception:
        return None


def looks_like_html(text):
    text = text.lower()

    return (
        "<html" in text
        or "<!doctype html" in text
        or "<body" in text
    )


def verify_env(content):
    upper = content.upper()

    matches = [
        marker
        for marker in ENV_MARKERS
        if marker in upper
    ]

    return len(matches) >= 1


def verify_git_head(content):
    lower = content.lower()

    return any(
        marker.lower() in lower
        for marker in GIT_HEAD_MARKERS
    )


def verify_phpinfo(content):
    return any(
        marker.lower() in content.lower()
        for marker in PHPINFO_MARKERS
    )


def verify_sql(content):
    lower = content.lower()

    markers = [
        "create table",
        "insert into",
        "drop table",
        "alter table"
    ]

    return any(
        marker in lower
        for marker in markers
    )


def verify_zip(response):
    content_type = response.headers.get(
        "Content-Type",
        ""
    ).lower()

    content = response.content[:4]

    return (
        "application/zip" in content_type
        or content.startswith(b"PK")
    )


def verify_config(content):
    lower = content.lower()

    markers = [
        "<?php",
        "db_password",
        "database_password",
        "define('db_",
        'define("db_'
    ]

    return any(
        marker in lower
        for marker in markers
    )


def is_real_exposure(
    name,
    response
):
    """
    Prevents false positives caused by:
    - custom 404 pages
    - redirects to homepage
    - generic HTML pages
    """

    if response.status_code != 200:
        return False

    content = response.text[
        :200_000
    ]

    if name == ".env":
        return verify_env(
            content
        )

    if name == "git_head":
        return verify_git_head(
            content
        )

    if name == "phpinfo":
        return verify_phpinfo(
            content
        )

    if name == "database_sql":
        return verify_sql(
            content
        )

    if name == "backup_zip":
        return verify_zip(
            response
        )

    if name == "config_php":
        return verify_config(
            content
        )

    return False


def check_file_exposure(url):
    """
    Checks a small fixed list of common
    accidental sensitive-file exposures.

    Returns:
        {
            status,
            score,
            checked_count,
            exposed_count,
            exposed_files,
            results
        }
    """

    result = {
        "status": "Not Checked",
        "score": 0,

        "checked_count": 0,
        "exposed_count": 0,

        "exposed_files": [],
        "results": []
    }

    base_url = build_base_url(
        url
    )

    if not base_url:
        result["status"] = "Invalid URL"
        return result

    total_score = 0

    for name, config in CHECK_PATHS.items():

        target_url = urljoin(
            base_url,
            config["path"]
        )

        entry = {
            "name": name,
            "path": config["path"],
            "url": target_url,

            "status_code": None,
            "exposed": False
        }

        try:
            response = safe_requests.get(
                target_url,

                timeout=4,

                allow_redirects=False,

                headers={
                    "User-Agent": (
                        "Mozilla/5.0 "
                        "(compatible; URLSecurityAnalyzer/2.0)"
                    )
                }
            )

            entry["status_code"] = (
                response.status_code
            )

            result["checked_count"] += 1

            exposed = is_real_exposure(
                name,
                response
            )

            entry["exposed"] = exposed

            if exposed:
                result["exposed_files"].append(
                    {
                        "name": name,
                        "path": config["path"],
                        "url": target_url
                    }
                )

                total_score += config[
                    "severity"
                ]

        except requests.Timeout:

            entry["status_code"] = (
                "Timeout"
            )

        except requests.RequestException:

            entry["status_code"] = (
                "Request Failed"
            )

        except Exception:

            entry["status_code"] = (
                "Unknown Error"
            )

        result["results"].append(
            entry
        )

    result["exposed_count"] = len(
        result["exposed_files"]
    )

    result["score"] = min(
        total_score,
        20
    )

    if result["exposed_count"] == 0:

        result["status"] = (
            "🟢 No Sensitive File Exposure Detected"
        )

    elif result["score"] <= 6:

        result["status"] = (
            "🟡 Possible Sensitive File Exposure"
        )

    elif result["score"] <= 12:

        result["status"] = (
            "🟠 Sensitive File Exposure Detected"
        )

    else:

        result["status"] = (
            "🔴 Critical Sensitive File Exposure"
        )

    return result