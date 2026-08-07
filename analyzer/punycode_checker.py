from urllib.parse import urlparse


def extract_hostname(url):

    try:

        hostname = urlparse(url).hostname

        if not hostname:

            return None

        return hostname.lower()

    except Exception:

        return None


def check_punycode(url):

    """
    Detects Punycode domains.

    Returns

        detected,
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

        labels = hostname.split(".")

        punycode_labels = [

            label

            for label in labels

            if label.startswith("xn--")

        ]

        if not punycode_labels:

            return (

                False,

                "🟢 No Punycode Detected",

                0

            )

        if len(punycode_labels) == 1:

            return (

                True,

                "🟡 Punycode Domain Detected",

                15

            )

        return (

            True,

            "🔴 Multiple Punycode Labels Detected",

            25

        )

    except Exception:

        return (

            False,

            "Not Checked",

            0

        )