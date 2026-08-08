import unicodedata

from urllib.parse import urlparse


CONFUSABLE_SCRIPTS = {
    "Latin",
    "Cyrillic",
    "Greek",
    "Armenian"
}


def extract_hostname(url):
    try:
        hostname = urlparse(url).hostname

        if not hostname:
            return None

        hostname = hostname.lower().rstrip(".")

        if hostname.startswith("www."):
            hostname = hostname[4:]

        return hostname

    except Exception:
        return None


def decode_hostname(hostname):
    labels = []

    for label in hostname.split("."):
        if label.startswith("xn--"):
            try:
                label = (
                    label
                    .encode("ascii")
                    .decode("idna")
                )

            except Exception:
                pass

        labels.append(label)

    return ".".join(labels)


def contains_non_ascii(text):
    return any(
        ord(character) > 127
        for character in text
    )


def get_script(character):
    if not character.isalpha():
        return None

    if character.isascii():
        return "Latin"

    try:
        name = unicodedata.name(
            character
        )

    except ValueError:
        return None

    if "LATIN" in name:
        return "Latin"

    if "CYRILLIC" in name:
        return "Cyrillic"

    if "GREEK" in name:
        return "Greek"

    if "ARMENIAN" in name:
        return "Armenian"

    if "ARABIC" in name:
        return "Arabic"

    if "HEBREW" in name:
        return "Hebrew"

    if (
        "HIRAGANA" in name
        or "KATAKANA" in name
        or "CJK" in name
        or "IDEOGRAPH" in name
    ):
        return "CJK"

    if "HANGUL" in name:
        return "Hangul"

    return "Other"


def contains_confusable_script_mix(text):
    scripts = {
        script
        for character in text
        if (
            script := get_script(
                character
            )
        )
    }

    confusable = (
        scripts
        & CONFUSABLE_SCRIPTS
    )

    return len(confusable) > 1


def check_homograph(url):
    try:
        hostname = extract_hostname(url)

        if not hostname:
            return (
                False,
                "Not Checked",
                0
            )

        decoded_hostname = decode_hostname(
            hostname
        )

        has_unicode = contains_non_ascii(
            decoded_hostname
        )

        mixed_scripts = (
            contains_confusable_script_mix(
                decoded_hostname
            )
        )

        if has_unicode and mixed_scripts:
            return (
                True,
                "🔴 Possible Unicode Homograph Attack",
                25
            )

        if has_unicode:
            return (
                True,
                "🟡 Internationalized Domain Characters Detected",
                10
            )

        return (
            False,
            "🟢 No Homograph Detected",
            0
        )

    except Exception:
        return (
            False,
            "Not Checked",
            0
        )