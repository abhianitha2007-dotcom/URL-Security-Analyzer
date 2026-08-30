"""Capture one bounded, immutable webpage snapshot per analysis."""

import hashlib
import requests

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from analyzer.exceptions import AnalysisIncompleteError
from analyzer.safe_http import safe_requests


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36 URLSecurityAnalyzer/4.0"
)
MAX_SNAPSHOT_BYTES = 5_000_000
INCOMPLETE_STATUS_CODES = {401, 403, 407, 408, 425, 429}


class FrozenHeaders(Mapping):
    """Read-only, case-insensitive response headers."""

    def __init__(self, headers):
        self._items = {
            str(name).lower(): (str(name), str(value))
            for name, value in headers.items()
        }

    def __getitem__(self, key):
        return self._items[str(key).lower()][1]

    def __iter__(self) -> Iterator[str]:
        return (original for original, _ in self._items.values())

    def __len__(self):
        return len(self._items)


@dataclass(frozen=True, slots=True)
class CookieSnapshot:
    name: str
    domain: str | None
    path: str | None
    secure: bool
    expires: int | None
    _rest: Mapping


@dataclass(frozen=True, slots=True)
class PageSnapshot:
    url: str
    status_code: int
    headers: Mapping
    content: bytes
    text: str
    history: tuple[int, ...]
    cookies: tuple[CookieSnapshot, ...]


def _freeze_response(response):
    cookies = tuple(
        CookieSnapshot(
            name=cookie.name,
            domain=cookie.domain,
            path=cookie.path,
            secure=bool(cookie.secure),
            expires=cookie.expires,
            _rest=MappingProxyType(dict(getattr(cookie, "_rest", {}) or {})),
        )
        for cookie in response.cookies
    )
    return PageSnapshot(
        url=str(response.url),
        status_code=int(response.status_code),
        headers=FrozenHeaders(response.headers),
        content=bytes(response.content),
        text=str(response.text),
        history=tuple(int(item.status_code) for item in response.history),
        cookies=cookies,
    )


def capture_page(url):
    try:
        response = safe_requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
    except requests.Timeout as error:
        raise AnalysisIncompleteError(
            "The website timed out before a complete snapshot could be captured. "
            "No risk score was produced.",
            ("page_snapshot",),
        ) from error
    except requests.RequestException as error:
        raise AnalysisIncompleteError(
            "The website could not be reached for complete analysis. "
            "No risk score was produced.",
            ("page_snapshot",),
        ) from error
    except Exception as error:
        raise AnalysisIncompleteError(
            "The webpage snapshot could not be captured safely. "
            "No risk score was produced.",
            ("page_snapshot",),
        ) from error

    if response.status_code >= 500 or response.status_code in INCOMPLETE_STATUS_CODES:
        raise AnalysisIncompleteError(
            f"The website returned HTTP {response.status_code}. "
            "The actual page could not be captured completely, so no score was produced.",
            ("page_snapshot",),
        )
    if len(response.content) > MAX_SNAPSHOT_BYTES:
        raise AnalysisIncompleteError(
            "The webpage is too large to analyze completely and safely. "
            "No risk score was produced.",
            ("page_snapshot",),
        )
    return _freeze_response(response)


def snapshot_metadata(response):
    return {
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type", "Unknown"),
        "redirect_count": len(response.history),
        "body_sha256": hashlib.sha256(response.content).hexdigest(),
    }
