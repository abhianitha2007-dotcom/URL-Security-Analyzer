import unicodedata

from urllib.parse import urlparse


def extract_hostname(url):

    try:

        hostname = urlparse(url).hostname

        if hostname:

            return hostname

        return None

    except Exception:

        return None


def contains_non_ascii(text):

    for character in text:

        if ord(character) > 127:

            return True

    return False


def contains_mixed_scripts(text):

    scripts = set()

    for character in text:

        if character.isascii():

            scripts.add("Latin")

            continue

        try:

            name = unicodedata.name(character)

        except ValueError:

            continue

        if "CYRILLIC" in name:

            scripts.add("Cyrillic")

        elif "GREEK" in name:

            scripts.add("Greek")

        elif "ARMENIAN" in name:

            scripts.add("Armenian")

        else:

            scripts.add("Other")

    return len(scripts) > 1


def check_homograph(url):

    """
    Returns

        has_homograph,
        status,
        score

    """

    try:

        hostname = extract_hostname(url)

        if not hostname:

            return (

                False,

                "Not Checked",

                0

            )

        if hostname.startswith("www."):

            hostname = hostname[4:]

        has_unicode = contains_non_ascii(hostname)

        mixed_scripts = contains_mixed_scripts(hostname)

        if has_unicode and mixed_scripts:

            return (

                True,

                "🔴 Possible Unicode Homograph Attack",

                25

            )

        if has_unicode:

            return (

                True,

                "🟡 Unicode Characters Detected",

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