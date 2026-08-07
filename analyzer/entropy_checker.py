import math
import re

from collections import Counter
from urllib.parse import urlparse


def calculate_entropy(text):

    """
    Calculates Shannon entropy.

    Higher entropy means the text
    appears more random.

    Returns:
        float
    """

    if not text:

        return 0.0

    frequencies = Counter(text)

    length = len(text)

    entropy = 0.0

    for count in frequencies.values():

        probability = count / length

        entropy -= probability * math.log2(probability)

    return round(entropy, 2)


def extract_domain_label(url):

    """
    Extracts the main hostname label
    used for randomness analysis.

    Example:
        login-x82kq.example.com
        -> login-x82kq

    Returns:
        string
    """

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


def count_character_types(text):

    """
    Counts letters, digits and special characters.

    Returns:
        letters,
        digits,
        special_characters
    """

    letters = sum(character.isalpha() for character in text)

    digits = sum(character.isdigit() for character in text)

    special_characters = sum(

        not character.isalnum()

        for character in text

    )

    return letters, digits, special_characters


def has_long_random_sequence(text):

    """
    Detects long mixed letter-number sequences.

    Examples:
        x8k29sd91
        ab32kd90x

    Returns:
        True / False
    """

    pattern = r"[a-z0-9]{10,}"

    matches = re.findall(pattern, text.lower())

    for match in matches:

        has_letter = any(character.isalpha() for character in match)

        has_digit = any(character.isdigit() for character in match)

        if has_letter and has_digit:

            return True

    return False


def check_entropy(url):

    """
    Analyzes whether the domain appears
    randomly generated.

    Returns:

        entropy,
        status,
        score
    """

    try:

        domain_label = extract_domain_label(url)

        if not domain_label:

            return (

                0.0,

                "Not Checked",

                0

            )

        entropy = calculate_entropy(domain_label)

        letters, digits, special_characters = (

            count_character_types(domain_label)

        )

        length = len(domain_label)

        digit_ratio = digits / length if length else 0

        random_sequence = has_long_random_sequence(domain_label)

        score = 0

        reasons = []

        if entropy >= 4.0:

            score += 12

            reasons.append("high character randomness")

        elif entropy >= 3.5:

            score += 6

            reasons.append("moderate character randomness")

        if digit_ratio >= 0.40:

            score += 8

            reasons.append("large number of digits")

        elif digit_ratio >= 0.25:

            score += 4

            reasons.append("several digits")

        if random_sequence:

            score += 10

            reasons.append("random letter-number sequence")

        if special_characters >= 3:

            score += 4

            reasons.append("many separators")

        score = min(score, 25)

        if score >= 18:

            status = "🔴 Highly Random Domain"

        elif score >= 8:

            status = "🟡 Moderately Random Domain"

        else:

            status = "🟢 Domain Pattern Looks Normal"

        if reasons:

            status += " — " + ", ".join(reasons)

        return (

            entropy,

            status,

            score

        )

    except Exception:

        return (

            0.0,

            "Not Checked",

            0

        )