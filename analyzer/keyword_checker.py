"""Data-driven URL language analysis.

The public ``check_keywords`` function is retained for compatibility, but the
result now comes from the versioned lexical model rather than a fixed word set.
"""

from analyzer.url_language_model import analyze_url_language


def check_keywords(url):
    result = analyze_url_language(url)
    return result["count"], result["matches"]


def check_url_language(url):
    return analyze_url_language(url)
