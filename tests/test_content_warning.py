from analyzer.content_warning import classify_content
from analyzer.risk_engine import calculate_risk


class HtmlResponse:
    headers = {"Content-Type": "text/html"}
    text = (
        "<html><head><meta name='rating' content='adult'>"
        "<title>Adults only</title></head></html>"
    )


def test_adult_warning_is_clear_and_separate_from_threat():
    warning = classify_content(
        "https://example.com/",
        threat_intelligence={"categories": []},
        response=HtmlResponse(),
    )

    assert warning["show"] is True
    assert warning["type"] == "adult"
    assert warning["title"] == "Adult / 18+ Content"
    assert "does not by itself mean" in warning["not_threat_verdict"]

    risk_score, verdict, _ = calculate_risk(
        {
            "https": {"detected": True},
            "ip_address": {"detected": False},
            "content_warning": warning,
            "threat_intelligence": {"checked": True, "report_found": False},
        }
    )
    assert risk_score == 0
    assert verdict == "Safe"


def test_reputation_category_can_trigger_gambling_warning():
    warning = classify_content(
        "https://example.com/",
        threat_intelligence={"categories": ["gambling and betting"]},
    )

    assert warning["show"] is True
    assert warning["type"] == "gambling"
    assert warning["evidence"] == ["reputation category"]


def test_ordinary_adult_education_phrase_is_not_age_restricted():
    warning = classify_content(
        "https://example.edu/adult-education",
        threat_intelligence={"categories": ["education"]},
    )

    assert warning["show"] is False
