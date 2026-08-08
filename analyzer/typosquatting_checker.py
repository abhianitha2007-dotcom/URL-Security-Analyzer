import re

from urllib.parse import urlparse


MULTI_LEVEL_SUFFIXES = {
    "co.in",
    "com.in",
    "org.in",
    "net.in",
    "gov.in",
    "nic.in",
    "ac.in",
    "edu.in",
    "res.in",
    "firm.in",
    "gen.in",
    "ind.in",
    "mil.in",

    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",

    "com.au",
    "net.au",
    "org.au",

    "co.jp",
    "ne.jp",
    "or.jp"
}


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

        hostname = hostname.lower().rstrip(".")

        if hostname.startswith("www."):
            hostname = hostname[4:]

        parts = hostname.split(".")

        if len(parts) < 2:
            return parts[0]

        suffix = ".".join(parts[-2:])

        if suffix in MULTI_LEVEL_SUFFIXES:
            if len(parts) >= 3:
                return parts[-3]

            return ""

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
        re.search(
            r"(.)\1{2,}",
            text
        )
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
    return (
        text.count("-")
        + text.count("_")
    ) >= 3


def check_typosquatting(url):
    try:
        domain_label = extract_domain_label(url)

        if not domain_label:
            return (
                False,
                "Not Checked",
                0
            )

        if domain_label.startswith("xn--"):
            return (
                False,
                "🟢 Punycode Handled Separately",
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

        if has_repeated_characters(
            domain_label
        ):
            score += 8
            reasons.append(
                "repeated characters"
            )

        if has_letter_digit_mixing(
            domain_label
        ):
            score += 5
            reasons.append(
                "mixed letters and digits"
            )

        if has_excessive_separators(
            domain_label
        ):
            score += 6
            reasons.append(
                "excessive separators"
            )

        score = min(
            score,
            25
        )

        if score >= 16:
            status = (
                "🔴 Strong Typosquatting Indicators"
            )

            detected = True

        elif score >= 7:
            status = (
                "🟡 Possible Typosquatting Pattern"
            )

            detected = True

        else:
            return (
                False,
                "🟢 No Typosquatting Pattern Detected",
                0
            )

        if reasons:
            status += (
                " — "
                + ", ".join(reasons)
            )

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