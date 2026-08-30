"""Backward-compatible URL-language evidence adapter.

The previous implementation embedded brand and phishing-word allowlists. Brand
coverage inevitably became stale and normal login URLs were mislabeled. The
versioned lexical model now supplies contextual evidence instead.
"""

from analyzer.url_language_model import analyze_url_language


def check_domain_similarity(url):
    analysis = analyze_url_language(url)
    evidence = analysis["evidence_tokens"]

    # The risk engine applies the model once, with corroboration. This adapter
    # is display-only so it must never double-count the same evidence.
    return evidence, analysis["status"], 0
