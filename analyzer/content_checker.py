"""Analyze page text availability without a hardcoded phishing phrase list."""

import requests
from bs4 import BeautifulSoup

from analyzer.safe_http import safe_requests


def fetch_page_text(url, response=None):
    if response is None:
        response = safe_requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 URLSecurityAnalyzer/4.0"},
        )

    content_type = response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
        return None

    soup = BeautifulSoup(response.text[:1_000_000], "html.parser")
    for element in soup(["script", "style", "noscript", "template"]):
        element.decompose()
    return " ".join(soup.stripped_strings).lower()


def check_content(url, response=None):
    """Return display metadata; page wording is not direct threat evidence."""
    try:
        text = fetch_page_text(url, response=response)
        if text is None:
            return [], "Not applicable — response is not HTML", 0
        if not text:
            return [], "HTML page contains no visible text", 0
        return [], "Visible page text analyzed without keyword rules", 0
    except requests.RequestException:
        return [], "Not checked — request failed", 0
    except Exception:
        return [], "Not checked — page parsing failed", 0
