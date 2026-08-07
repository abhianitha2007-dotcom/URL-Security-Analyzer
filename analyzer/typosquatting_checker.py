import re

from urllib.parse import urlparse


COMMON_SUBSTITUTIONS = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b"
}


def extract_domain_label(url):
    try:
        hostname = urlparse(url).hostname

        if not hostname:
            return ""

        hostname = hostname.lower()

        if hostname.startswith("www."):
            hostname = hostname[4:]

        parts = hostname.split(".")

        if len(parts) < 2:
            return parts[0]

        return parts[-2]

    except Exception:
        return ""


def count_digit_substitutions(text):
    return sum(
        character in COMMON_SUBSTITUTIONS
        for character in text
    )


def has_repeated_characters(text):
    return bool(
        re.search(r"(.)\1{2,}", text)
    )


def has_letter_digit_mixing(text):
    has_letters = any(
        character.isalpha()
        for character in text
    )

    has_digits = any(
        character.isdigit()
        for character in text
    )

    return has_letters and has_digits


def has_excessive_separators(text):
    separator_count = (
        text.count("-")
        + text.count("_")
    )

    return separator_count >= 3


def check_typosquatting(url):
    """
    Checks generic typosquatting indicators.

    Returns:
        detected,
        status,
        score
    """

    try:
        domain_label = extract_domain_label(url)

        if not domain_label:
            return (
                False,
                "Not Checked",
                0
            )

        score = 0
        reasons = []

        substitutions = count_digit_substitutions(
            domain_label
        )

        if substitutions >= 2:
            score += 12
            reasons.append(
                "multiple letter-number substitutions"
            )

        elif substitutions == 1:
            score += 5
            reasons.append(
                "possible letter-number substitution"
            )

        if has_repeated_characters(domain_label):
            score += 8
            reasons.append(
                "repeated characters"
            )

        if has_letter_digit_mixing(domain_label):
            score += 5
            reasons.append(
                "mixed letters and digits"
            )

        if has_excessive_separators(domain_label):
            score += 6
            reasons.append(
                "excessive separators"
            )

        score = min(score, 25)

        if score >= 16:
            status = "🔴 Strong Typosquatting Indicators"
            detected = True

        elif score >= 7:
            status = "🟡 Possible Typosquatting Pattern"
            detected = True

        else:
            status = "🟢 No Typosquatting Pattern Detected"
            detected = False

        if reasons:
            status += " — " + ", ".join(reasons)

        return (
            detected,
            status,
            score
        )

    except Exception:
        return (
            False,
            "Not Checked",
            0
        )