import threading
import time
from types import SimpleNamespace

import analyzer.file_exposure_checker as exposure
import analyzer.sitemap_checker as sitemap


def test_exposure_probes_run_concurrently_and_keep_stable_order(monkeypatch):
    lock = threading.Lock()
    active = 0
    maximum_active = 0

    def fake_get(url, **kwargs):
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return SimpleNamespace(
            status_code=404,
            headers={"Content-Type": "text/html"},
            content=b"",
            text="",
        )

    monkeypatch.setattr(exposure.safe_requests, "get", fake_get)

    result = exposure.check_file_exposure("https://example.com")

    assert maximum_active > 1
    assert result["checked_count"] == len(exposure.CHECK_PATHS)
    assert [entry["name"] for entry in result["results"]] == list(
        exposure.CHECK_PATHS
    )
    assert result["score"] == 0


def test_restricted_sitemap_is_a_completed_observation(monkeypatch):
    monkeypatch.setattr(
        sitemap.safe_requests,
        "get",
        lambda *args, **kwargs: SimpleNamespace(
            status_code=403,
            url="https://example.com/sitemap.xml",
            content=b"",
        ),
    )

    result = sitemap.check_sitemap("https://example.com")

    assert result["checked"] is True
    assert result["found"] is False
    assert result["status"] == "⚪ Sitemap Access Restricted"
