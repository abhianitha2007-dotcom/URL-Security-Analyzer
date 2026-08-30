from types import SimpleNamespace
from dataclasses import FrozenInstanceError

import pytest

import analyzer.detection_manager as manager
import analyzer.page_snapshot as page_snapshot
from analyzer.exceptions import AnalysisIncompleteError
from analyzer.page_snapshot import _freeze_response


class PageResponse:
    url = "https://example.com/final"
    status_code = 200
    history = [SimpleNamespace(status_code=301)]
    headers = {"Content-Type": "text/html; charset=utf-8"}
    content = b"<html><title>Example</title><p>Stable page.</p></html>"
    text = content.decode()
    cookies = []


def test_page_snapshot_is_frozen_and_headers_remain_case_insensitive():
    response = SimpleNamespace(
        url="https://example.com/final",
        status_code=200,
        history=[SimpleNamespace(status_code=301)],
        headers={"content-type": "text/html", "X-Test": "yes"},
        content=b"<html></html>",
        text="<html></html>",
        cookies=[],
    )

    snapshot = _freeze_response(response)

    assert snapshot.headers.get("Content-Type") == "text/html"
    assert snapshot.headers.get("x-test") == "yes"
    assert snapshot.history == (301,)
    with pytest.raises(FrozenInstanceError):
        snapshot.url = "https://changed.example"
    with pytest.raises(TypeError):
        snapshot.headers["X-Test"] = "changed"


@pytest.mark.parametrize("status_code", [403, 429, 503])
def test_blocked_or_unavailable_page_never_becomes_a_score(
    monkeypatch,
    status_code,
):
    response = SimpleNamespace(
        url="https://example.com",
        status_code=status_code,
        history=[],
        headers={"Content-Type": "text/html"},
        content=b"blocked",
        text="blocked",
        cookies=[],
    )
    monkeypatch.setattr(page_snapshot.safe_requests, "get", lambda *args, **kwargs: response)

    with pytest.raises(AnalysisIncompleteError) as captured:
        page_snapshot.capture_page("https://example.com")

    assert captured.value.failed_checks == ("page_snapshot",)
    assert "no score" in captured.value.message.lower()


def test_page_snapshot_follows_safe_html_refresh(monkeypatch):
    redirect_html = (
        '<html><head><meta http-equiv="refresh" '
        'content="0; url=https://portal.example/home"></head></html>'
    )
    responses = iter([
        SimpleNamespace(
            url="https://legacy.example/",
            status_code=200,
            history=[],
            headers={"Content-Type": "text/html"},
            content=redirect_html.encode(),
            text=redirect_html,
            cookies=[],
        ),
        SimpleNamespace(
            url="https://portal.example/home",
            status_code=200,
            history=[],
            headers={"Content-Type": "text/html"},
            content=b"<html><p>Portal home</p></html>",
            text="<html><p>Portal home</p></html>",
            cookies=[],
        ),
    ])
    requested = []

    def fake_get(url, **kwargs):
        requested.append(url)
        return next(responses)

    monkeypatch.setattr(page_snapshot.safe_requests, "get", fake_get)

    snapshot = page_snapshot.capture_page("https://legacy.example/")

    assert requested == [
        "https://legacy.example/",
        "https://portal.example/home",
    ]
    assert snapshot.url == "https://portal.example/home"
    assert snapshot.history == (200,)
    assert "Portal home" in snapshot.text


def test_page_modules_share_one_snapshot(monkeypatch):
    page = PageResponse()
    captures = []
    consumers = {}

    monkeypatch.setattr(
        manager,
        "capture_page",
        lambda url: captures.append(url) or page,
    )

    page_results = {
        "check_redirects": (1, page.url, "Complete", 0),
        "check_shortener": (False, "Complete", 0),
        "check_javascript": ([], "Complete", 0),
        "check_forms": ([], "Complete", 0),
        "check_content": ([], "Complete", 0),
        "check_favicon": (None, "Complete", 0),
        "check_security_headers": ([], "Complete", 0),
        "check_response_headers": {"status": "Complete", "score": 0},
        "check_technology": {"status": "Complete", "score": 0},
        "check_cookie_security": {"status": "Complete", "score": 0},
        "check_mixed_content": {"status": "Complete", "score": 0},
    }

    for function_name, return_value in page_results.items():
        def checker(url, response, *, _name=function_name, _result=return_value):
            consumers[_name] = response
            return _result

        monkeypatch.setattr(manager, function_name, checker)

    monkeypatch.setattr(
        manager,
        "check_domain_age",
        lambda url: {"confirmed_new": False, "message": "Established domain"},
    )
    monkeypatch.setattr(manager, "get_whois_info", lambda url: {"status": "Known"})
    monkeypatch.setattr(manager, "get_dns_records", lambda url: {"A": ["93.184.216.34"]})
    monkeypatch.setattr(
        manager,
        "get_ssl_info",
        lambda url: {"status": "Valid SSL certificate"},
    )
    monkeypatch.setattr(
        manager,
        "check_robots",
        lambda url: {"status": "No robots.txt found", "sitemap_urls": []},
    )
    monkeypatch.setattr(
        manager,
        "check_sitemap",
        lambda url, discovered_sitemaps=None: {
            "checked": True,
            "status": "Sitemap not found",
            "errors": [],
        },
    )
    monkeypatch.setattr(
        manager,
        "check_file_exposure",
        lambda url: {"status": "Complete", "checked_count": 0, "results": []},
    )
    monkeypatch.setattr(manager, "check_http_methods", lambda url: {"status": "Complete"})
    monkeypatch.setattr(manager, "check_cors_security", lambda url: {"status": "Complete"})
    monkeypatch.setattr(
        manager,
        "check_threat_intelligence",
        lambda url: {"checked": True, "status": "Complete", "categories": []},
    )

    result = manager.run_full_network_checks("https://example.com")

    assert captures == ["https://example.com"]
    assert set(consumers) == set(page_results)
    assert all(value is page for value in consumers.values())
    assert result["snapshot"]["redirect_count"] == 1
    assert len(result["snapshot"]["body_sha256"]) == 64
    assert result["redirects"] == {
        "count": 1,
        "final_url": page.url,
        "status": "Complete",
        "score": 0,
    }
    assert result["forms"] == {
        "issues": [],
        "status": "Complete",
        "score": 0,
    }
    assert result["javascript"] == {
        "patterns": [],
        "status": "Complete",
        "score": 0,
    }
    assert result["security_headers"] == {
        "missing": [],
        "status": "Complete",
        "score": 0,
    }


def test_required_module_exception_is_not_replaced_with_zero():
    from concurrent.futures import Future

    future = Future()
    future.set_exception(RuntimeError("checker crashed"))

    with pytest.raises(AnalysisIncompleteError) as captured:
        manager._required(future, "javascript")

    assert captured.value.failed_checks == ("javascript",)
    assert "No risk score" in captured.value.message


def test_malformed_legacy_checker_result_never_becomes_a_score():
    with pytest.raises(AnalysisIncompleteError) as captured:
        manager._normalize_network_result(
            "redirects",
            (1, "https://example.com"),
        )

    assert captured.value.failed_checks == ("redirects",)
    assert "No risk score" in captured.value.message
