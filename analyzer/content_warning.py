"""Versioned content classification kept separate from threat scoring."""

import json
import re

from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup


POLICY_PATH = Path(__file__).resolve().parent / "data" / "content_policy.json"


@lru_cache(maxsize=1)
def load_content_policy():
    with POLICY_PATH.open(encoding="utf-8") as source:
        policy = json.load(source)
    if not policy.get("policy_version") or not isinstance(policy.get("categories"), list):
        raise ValueError("Content-warning policy is invalid.")
    return policy


def _tokens(value):
    return set(re.findall(r"[a-z0-9+]+", unquote(value).lower()))


def _page_metadata(response):
    if response is None:
        return ""
    content_type = response.headers.get("Content-Type", "").lower()
    if "html" not in content_type:
        return ""
    soup = BeautifulSoup(response.text[:500_000], "html.parser")
    values = [soup.title.get_text(" ", strip=True) if soup.title else ""]
    for tag in soup.find_all("meta"):
        key = str(tag.get("name") or tag.get("property") or "").lower()
        if key in {"description", "keywords", "rating", "classification", "og:title", "og:description"}:
            values.append(f"{key}:{tag.get('content') or ''}")
    return " ".join(values).lower()


def classify_content(url, threat_intelligence=None, response=None):
    policy = load_content_policy()
    intelligence = threat_intelligence if isinstance(threat_intelligence, dict) else {}
    categories = intelligence.get("categories", [])
    if not isinstance(categories, list):
        categories = []

    category_text = " ".join(str(item).lower() for item in categories)
    metadata = _page_metadata(response)
    try:
        parsed = urlsplit(url)
        url_tokens = _tokens(f"{parsed.hostname or ''} {parsed.path} {parsed.query}")
    except (TypeError, ValueError):
        url_tokens = _tokens(str(url))

    matches = []
    for rule in policy["categories"]:
        sources = []
        if any(term in category_text for term in rule.get("category_terms", [])):
            sources.append("reputation category")
        if any(term in metadata for term in rule.get("metadata_terms", [])):
            sources.append("page metadata")
        if url_tokens.intersection(rule.get("url_tokens", [])):
            sources.append("URL context")
        if sources:
            matches.append((int(rule.get("priority", 0)), rule, sources))

    if not matches:
        return {
            "show": False,
            "type": None,
            "icon": None,
            "title": "No content warning detected",
            "message": "No age-restricted or sensitive content category was identified.",
            "evidence": [],
            "policy_version": policy["policy_version"],
        }

    _, rule, sources = max(matches, key=lambda item: item[0])
    return {
        "show": True,
        "type": rule["id"],
        "icon": rule["icon"],
        "title": rule["label"],
        "message": rule["message"],
        "evidence": sources,
        "policy_version": policy["policy_version"],
        "not_threat_verdict": "This content label does not by itself mean the website is malicious.",
    }
