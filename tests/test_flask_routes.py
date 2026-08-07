import os
from pathlib import Path

import pytest


# =========================================================
# TEST ENVIRONMENT
# =========================================================

# app.py requires SECRET_KEY at import time.
# This value exists only inside the pytest process.
os.environ.setdefault(
    "SECRET_KEY",
    "pytest-only-secret-key"
)

os.environ.setdefault(
    "SESSION_COOKIE_SECURE",
    "false"
)

os.environ.setdefault(
    "FLASK_DEBUG",
    "false"
)


import app as app_module


# =========================================================
# FIXTURES
# =========================================================

@pytest.fixture
def client():

    app_module.app.config.update(
        TESTING=True,
        SESSION_COOKIE_SECURE=False
    )

    with app_module.app.test_client() as test_client:

        yield test_client


def fake_analysis_results():
    """
    Minimum complete result structure required by app.py.
    """

    return {

        "https": {
            "status": "✅ HTTPS Detected"
        },

        "ip_address": {
            "status": "✅ Domain Name Used"
        },

        "keywords": {
            "count": 0,
            "matches": []
        },

        "url_length": {
            "length": 19,
            "status": "🟢 Short"
        },

        "subdomains": {
            "count": 0,
            "status": "🟢 Normal"
        },

        "at_symbol": {
            "status": "🟢 Not Detected"
        },

        "shortener": {
            "status": "🟢 Not Detected"
        },

        "hyphens": {
            "count": 0,
            "status": "🟢 Normal"
        },

        "domain_age": {
            "status": "🟢 Established Domain",
            "score": 0
        },

        "whois": {
            "status": "Checked"
        },

        "dns": {
            "status": "Checked"
        },

        "ssl": {
            "status": "Checked"
        },

        "tld": {
            "value": "com",
            "status": "🟢 Normal TLD"
        }
    }


# =========================================================
# HOME PAGE
# =========================================================

def test_home_page_loads(client):

    response = client.get("/")

    assert response.status_code == 200

    assert b"URL Security Analyzer" in response.data


# =========================================================
# SECURITY RESPONSE HEADERS
# =========================================================

def test_security_headers_are_added(client):

    response = client.get("/")

    assert (
        response.headers[
            "X-Content-Type-Options"
        ]
        == "nosniff"
    )

    assert (
        response.headers[
            "X-Frame-Options"
        ]
        == "DENY"
    )

    assert (
        response.headers[
            "Referrer-Policy"
        ]
        == "strict-origin-when-cross-origin"
    )

    assert (
        response.headers[
            "Permissions-Policy"
        ]
        == "camera=(), microphone=(), geolocation=()"
    )


# =========================================================
# PRIVATE / LOCAL URL REJECTION
# =========================================================

@pytest.mark.parametrize(
    "unsafe_url",
    [
        "http://127.0.0.1",
        "http://localhost",
        "http://192.168.1.1",
        "http://169.254.169.254",
    ]
)
def test_analyze_rejects_private_urls(
    client,
    monkeypatch,
    unsafe_url
):

    def analyzer_must_not_run(url):

        raise AssertionError(
            "run_all_checks() should not run "
            "for an unsafe URL."
        )


    monkeypatch.setattr(
        app_module,
        "run_all_checks",
        analyzer_must_not_run
    )


    response = client.post(
        "/analyze",
        data={
            "url": unsafe_url
        }
    )


    assert response.status_code == 200

    assert (
        b"valid public HTTP or HTTPS URL"
        in response.data
    )


# =========================================================
# EMPTY URL
# =========================================================

def test_analyze_rejects_empty_url(
    client
):

    response = client.post(
        "/analyze",
        data={
            "url": ""
        }
    )

    assert response.status_code == 200

    assert (
        b"Please enter a URL"
        in response.data
    )


# =========================================================
# VALID ANALYSIS ROUTE
# =========================================================

def test_valid_analysis_route(
    client,
    monkeypatch,
    tmp_path
):

    captured = {}

    results = fake_analysis_results()


    def fake_validator(url):

        captured[
            "validated_url"
        ] = url

        return True


    def fake_run_all_checks(url):

        captured[
            "analyzed_url"
        ] = url

        return results


    def fake_calculate_risk(
        received_results
    ):

        assert (
            received_results
            is results
        )

        return (
            0,
            "Safe",
            []
        )


    def fake_save_scan(
        url,
        risk_score,
        verdict,
        history_session_id
    ):

        captured[
            "saved_scan"
        ] = (
            url,
            risk_score,
            verdict,
            history_session_id
        )

        return True


    def fake_generate_pdf(
        report_data,
        output_path
    ):

        captured[
            "report_data"
        ] = report_data

        Path(
            output_path
        ).write_bytes(
            b"%PDF-1.4\n% pytest"
        )


    def fake_report_path(
        filename
    ):

        return (
            tmp_path
            / filename
        )


    def fake_render_template(
        template_name,
        **context
    ):

        captured[
            "template"
        ] = template_name

        captured[
            "context"
        ] = context

        return "rendered-result"


    monkeypatch.setattr(
        app_module,
        "is_valid_url",
        fake_validator
    )

    monkeypatch.setattr(
        app_module,
        "run_all_checks",
        fake_run_all_checks
    )

    monkeypatch.setattr(
        app_module,
        "calculate_risk",
        fake_calculate_risk
    )

    monkeypatch.setattr(
        app_module,
        "save_scan",
        fake_save_scan
    )

    monkeypatch.setattr(
        app_module,
        "generate_pdf",
        fake_generate_pdf
    )

    monkeypatch.setattr(
        app_module,
        "get_report_path",
        fake_report_path
    )

    monkeypatch.setattr(
        app_module,
        "render_template",
        fake_render_template
    )


    response = client.post(
        "/analyze",
        data={
            "url": "example.com"
        }
    )


    assert response.status_code == 200

    assert (
        response.data
        == b"rendered-result"
    )


    # Missing scheme should be normalized.
    assert (
        captured[
            "validated_url"
        ]
        == "https://example.com"
    )

    assert (
        captured[
            "analyzed_url"
        ]
        == "https://example.com"
    )


    assert (
        captured[
            "template"
        ]
        == "result.html"
    )


    assert (
        captured[
            "context"
        ][
            "risk_score"
        ]
        == 0
    )

    assert (
        captured[
            "context"
        ][
            "verdict"
        ]
        == "Safe"
    )

    assert (
        captured[
            "context"
        ][
            "pdf_available"
        ]
        is True
    )


    saved_url, saved_score, saved_verdict, saved_sid = (
        captured[
            "saved_scan"
        ]
    )

    assert (
        saved_url
        == "https://example.com"
    )

    assert saved_score == 0
    assert saved_verdict == "Safe"
    assert saved_sid


# =========================================================
# HISTORY SESSION SCOPING
# =========================================================

def test_history_uses_browser_session_id(
    client,
    monkeypatch
):

    received_ids = []

    captured = {}


    def record_id(
        history_session_id
    ):

        received_ids.append(
            history_session_id
        )

        return []


    monkeypatch.setattr(
        app_module,
        "get_all_scans",
        record_id
    )

    monkeypatch.setattr(
        app_module,
        "get_total_scans",
        lambda sid: (
            received_ids.append(sid)
            or 0
        )
    )

    monkeypatch.setattr(
        app_module,
        "get_average_risk",
        lambda sid: (
            received_ids.append(sid)
            or 0
        )
    )

    monkeypatch.setattr(
        app_module,
        "get_highest_risk",
        lambda sid: (
            received_ids.append(sid)
            or 0
        )
    )

    monkeypatch.setattr(
        app_module,
        "get_lowest_risk",
        lambda sid: (
            received_ids.append(sid)
            or 0
        )
    )


    def fake_render_template(
        template_name,
        **context
    ):

        captured[
            "template"
        ] = template_name

        return "history-page"


    monkeypatch.setattr(
        app_module,
        "render_template",
        fake_render_template
    )


    response = client.get(
        "/history"
    )


    assert response.status_code == 200

    assert (
        captured[
            "template"
        ]
        == "history.html"
    )

    assert len(
        received_ids
    ) == 5

    assert all(
        received_ids[0] == value
        for value in received_ids
    )

    assert received_ids[0]


# =========================================================
# CSRF - DELETE SCAN
# =========================================================

def test_delete_scan_rejects_missing_csrf(
    client
):

    response = client.post(
        "/delete-scan/1"
    )

    assert response.status_code == 400


def test_delete_scan_with_valid_csrf(
    client,
    monkeypatch
):

    captured = {}


    monkeypatch.setattr(
        app_module,
        "delete_scan",
        lambda scan_id, sid:
            captured.update(
                {
                    "scan_id": scan_id,
                    "sid": sid
                }
            )
    )


    with client.session_transaction() as flask_session:

        flask_session[
            "_csrf_token"
        ] = "pytest-csrf-token"

        flask_session[
            "history_session_id"
        ] = "pytest-history-session"


    response = client.post(
        "/delete-scan/7",
        data={
            "csrf_token":
                "pytest-csrf-token"
        }
    )


    assert response.status_code == 302

    assert (
        captured[
            "scan_id"
        ]
        == 7
    )

    assert (
        captured[
            "sid"
        ]
        == "pytest-history-session"
    )


# =========================================================
# CSRF - CLEAR HISTORY
# =========================================================

def test_clear_history_rejects_missing_csrf(
    client
):

    response = client.post(
        "/clear-history"
    )

    assert response.status_code == 400


def test_clear_history_with_valid_csrf(
    client,
    monkeypatch
):

    captured = {}


    monkeypatch.setattr(
        app_module,
        "clear_history",
        lambda sid:
            captured.update(
                {
                    "sid": sid
                }
            )
    )


    with client.session_transaction() as flask_session:

        flask_session[
            "_csrf_token"
        ] = "pytest-clear-token"

        flask_session[
            "history_session_id"
        ] = "pytest-history-session"


    response = client.post(
        "/clear-history",
        data={
            "csrf_token":
                "pytest-clear-token"
        }
    )


    assert response.status_code == 302

    assert (
        captured[
            "sid"
        ]
        == "pytest-history-session"
    )


# =========================================================
# PDF DOWNLOAD
# =========================================================

def test_download_report_requires_existing_report(
    client
):

    response = client.get(
        "/download-report"
    )

    assert response.status_code == 400

    assert (
        b"No report is available"
        in response.data
    )


def test_download_existing_report(
    client,
    monkeypatch,
    tmp_path
):

    report_file = (
        tmp_path
        / "security_report_test.pdf"
    )

    report_file.write_bytes(
        b"%PDF-1.4\n% pytest"
    )


    monkeypatch.setattr(
        app_module,
        "get_report_path",
        lambda filename:
            report_file
    )


    with client.session_transaction() as flask_session:

        flask_session[
            "report_filename"
        ] = report_file.name


    response = client.get(
        "/download-report"
    )


    assert response.status_code == 200

    assert (
        response.headers[
            "Content-Disposition"
        ].startswith(
            "attachment;"
        )
    )


# =========================================================
# REQUEST SIZE LIMIT
# =========================================================

def test_oversized_request_is_rejected(
    client
):

    oversized_url = (
        "https://example.com/?q="
        + (
            "a"
            * 20000
        )
    )


    response = client.post(
        "/analyze",
        data={
            "url":
                oversized_url
        }
    )


    assert response.status_code == 413

    assert (
        b"too large"
        in response.data.lower()
    )