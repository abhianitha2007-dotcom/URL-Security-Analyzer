import pytest

from analyzer.domain_similarity_checker import check_domain_similarity
from analyzer.query_checker import check_query_parameters
from analyzer.tld_checker import check_tld
from analyzer.url_language_model import analyze_url_language


@pytest.mark.parametrize("url", [
    "https://example.xyz/login",
    "https://agency.gov.in/signin",
    "https://example.tk/",
])
def test_tld_never_assigns_threat_reputation(url):
    _, status, score = check_tld(url)

    assert score == 0
    assert "risk" not in status.lower()
    assert "official" not in status.lower()


def test_query_names_are_factual_not_suspicious():
    count, names, status, score = check_query_parameters(
        "https://example.com/callback?token=abc&redirect=/home"
    )

    assert count == 2
    assert names == ["redirect", "token"]
    assert score == 0
    assert "suspicious" not in status.lower()


def test_legacy_similarity_adapter_cannot_double_count_model():
    matches, _, score = check_domain_similarity(
        "https://paypal-login-security.xyz/"
    )

    assert isinstance(matches, list)
    assert score == 0


def test_url_language_model_is_repeatable():
    url = "https://secure-bank-login-update-account.com/"
    first = analyze_url_language(url)

    assert all(analyze_url_language(url) == first for _ in range(5))


def test_below_threshold_tokens_are_not_shown_as_suspicious():
    result = analyze_url_language("https://www.google.com/")

    assert result["probability"] < 0.65
    assert result["matches"] == []
    assert result["count"] == 0


def test_authoritative_subdomains_do_not_produce_lexical_alarms():
    result = analyze_url_language("https://accounts.google.com/")

    assert result["probability"] < 0.65
    assert result["matches"] == []
    assert "Elevated" not in result["status"]


def test_registrable_domain_extraction_handles_cc_tlds():
    from analyzer.whois_service import get_registrable_domain

    assert get_registrable_domain("ssp.postmatric.karnataka.gov.in") == "karnataka.gov.in"
    assert get_registrable_domain("accounts.google.com") == "google.com"
    assert get_registrable_domain("sub.domain.co.uk") == "domain.co.uk"
