import re

from urllib.parse import unquote, urlparse


EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)


def check_email_address(url):

    """
    Detects email addresses inside the URL.

    Returns:
        detected_emails,
        status,
        score
    """

    try:
        parsed = urlparse(url)

        text = " ".join([
            unquote(parsed.netloc),
            unquote(parsed.path),
            unquote(parsed.query)
        ])

        detected = sorted(
            set(EMAIL_PATTERN.findall(text))
        )

        count = len(detected)

        if count == 0:
            return (
                [],
                "🟢 No Email Address Detected",
                0
            )

        if count == 1:
            return (
                detected,
                "🟡 Email Address Present in URL",
                5
            )

        return (
            detected,
            "🟠 Multiple Email Addresses Present",
            10
        )

    except Exception:
        return (
            [],
            "Not Checked",
            0
        )