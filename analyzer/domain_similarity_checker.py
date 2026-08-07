import re

from difflib import SequenceMatcher
from urllib.parse import urlparse


MULTI_LEVEL_SUFFIXES = {
    "co.in",
    "gov.in",
    "nic.in",
    "ac.in",
    "edu.in",
    "co.uk",
    "gov.uk",
    "org.uk",
    "com.au",
    "net.au",
    "co.jp"
}


PHISHING_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "support",
    "update",
    "confirm",
    "authentication",
    "password",
    "payment",
    "wallet",
    "bank",
    "recover",
    "unlock"
}


COMMON_BRANDS = {
    "google": {
        "google.com"
    },
    "microsoft": {
        "microsoft.com",
        "live.com",
        "outlook.com"
    },
    "apple": {
        "apple.com",
        "icloud.com"
    },
    "amazon": {
        "amazon.com",
        "amazon.in",
        "amazon.co.uk"
    },
    "paypal": {
        "paypal.com"
    },
    "facebook": {
        "facebook.com",
        "fb.com"
    },
    "instagram": {
        "instagram.com"
    },
    "whatsapp": {
        "whatsapp.com"
    },
    "linkedin": {
        "linkedin.com"
    },
    "github": {
        "github.com"
    },
    "netflix": {
        "netflix.com"
    },
    "dropbox": {
        "dropbox.com"
    },
    "sbi": {
        "sbi.co.in",
        "onlinesbi.sbi"
    },
    "hdfc": {
        "hdfcbank.com"
    },
    "icici": {
        "icicibank.com"
    }
}


SUBSTITUTION_OPTIONS = {
    "0": ("o",),
    "1": ("i", "l"),
    "2": ("z",),
    "3": ("e",),
    "4": ("a",),
    "5": ("s",),
    "6": ("g",),
    "7": ("t",),
    "8": ("b",),
    "9": ("g",)
}


def get_hostname(url):

    try:
        hostname = urlparse(url).hostname

        if hostname:
            return hostname.lower().strip(".")

        return ""

    except Exception:
        return ""


def get_registered_domain(hostname):

    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    last_two = ".".join(parts[-2:])

    if last_two in MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])

    return last_two


def get_domain_label(registered_domain):

    parts = registered_domain.split(".")

    if len(parts) < 2:
        return registered_domain

    last_two = ".".join(parts[-2:])

    if last_two in MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
        return parts[-3]

    return parts[-2]


def clean_text(text):

    return re.sub(
        r"[^a-z0-9]",
        "",
        text.lower()
    )


def generate_substitution_variants(text):

    variants = {""}

    for character in clean_text(text):

        replacements = SUBSTITUTION_OPTIONS.get(
            character,
            (character,)
        )

        new_variants = set()

        for prefix in variants:
            for replacement in replacements:
                new_variants.add(
                    prefix + replacement
                )

        variants = new_variants

        if len(variants) > 64:
            variants = set(
                list(variants)[:64]
            )

    return variants


def split_domain_words(text):

    return [
        word
        for word in re.split(
            r"[-_.]+",
            text.lower()
        )
        if word
    ]


def similarity(first, second):

    if not first or not second:
        return 0.0

    return SequenceMatcher(
        None,
        first,
        second
    ).ratio()


def find_phishing_words(hostname):

    words = split_domain_words(hostname)

    return sorted({
        word
        for word in words
        if word in PHISHING_WORDS
    })


def brand_matches_label(label, brand):

    brand = clean_text(brand)

    variants = generate_substitution_variants(
        label
    )

    for variant in variants:

        if brand in variant:
            return True

        if similarity(variant, brand) >= 0.82:
            return True

    return False


def find_brand_impersonation(
    hostname,
    registered_domain
):

    domain_label = get_domain_label(
        registered_domain
    )

    hostname_words = split_domain_words(
        hostname
    )

    detected = []

    for brand, official_domains in COMMON_BRANDS.items():

        if registered_domain in official_domains:
            continue

        label_match = brand_matches_label(
            domain_label,
            brand
        )

        word_match = any(
            brand_matches_label(word, brand)
            for word in hostname_words
        )

        if label_match or word_match:
            detected.append(brand)

    return sorted(set(detected))


def check_domain_similarity(url):

    """
    Returns:
        detected_matches,
        status,
        score
    """

    try:
        hostname = get_hostname(url)

        if not hostname:
            return (
                [],
                "Not Checked",
                0
            )

        registered_domain = get_registered_domain(
            hostname
        )

        phishing_words = find_phishing_words(
            hostname
        )

        impersonated_brands = find_brand_impersonation(
            hostname,
            registered_domain
        )

        detected = []

        for brand in impersonated_brands:
            detected.append(
                f"Possible {brand.title()} impersonation"
            )

        for word in phishing_words:
            detected.append(
                f"Suspicious word: {word}"
            )

        score = 0

        if impersonated_brands:
            score += 22

            if len(impersonated_brands) >= 2:
                score += 4

        phishing_count = len(phishing_words)

        if phishing_count == 1:
            score += 4

        elif phishing_count == 2:
            score += 8

        elif phishing_count >= 3:
            score += 12

        if impersonated_brands and phishing_words:
            score += 5

        score = min(score, 30)

        if score >= 24:
            status = (
                "🔴 Strong Brand Impersonation Indicators"
            )

        elif score >= 15:
            status = (
                "🟠 Possible Brand Impersonation"
            )

        elif score >= 6:
            status = (
                "🟡 Suspicious Domain Wording"
            )

        else:
            status = (
                "🟢 No Suspicious Domain Similarity"
            )

        return (
            detected,
            status,
            score
        )

    except Exception:
        return (
            [],
            "Not Checked",
            0
        )