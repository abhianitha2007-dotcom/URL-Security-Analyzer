from urllib.parse import parse_qs, urlparse


SUSPICIOUS_PARAMETERS = {
    "token",
    "session",
    "sessionid",
    "auth",
    "authentication",
    "password",
    "passwd",
    "otp",
    "pin",
    "redirect",
    "redirect_url",
    "return",
    "return_url",
    "next",
    "continue",
    "callback",
    "verify",
    "verification",
    "account",
    "email",
    "username",
    "userid"
}


def check_query_parameters(url):
    """
    Checks suspicious query parameters.

    Returns:
        parameter_count,
        suspicious_parameters,
        status,
        score
    """

    try:
        parsed = urlparse(url)
        parameters = parse_qs(parsed.query, keep_blank_values=True)

        if not parameters:
            return (
                0,
                [],
                "🟢 No Query Parameters",
                0
            )

        found = []

        for parameter in parameters:
            normalized = parameter.lower().strip()

            if normalized in SUSPICIOUS_PARAMETERS:
                found.append(normalized)

        found = sorted(set(found))
        count = len(found)

        if count == 0:
            return (
                0,
                [],
                "🟢 No Suspicious Parameters",
                0
            )

        if count == 1:
            return (
                1,
                found,
                "🟡 One Suspicious Parameter",
                5
            )

        if count <= 3:
            return (
                count,
                found,
                "🟠 Multiple Suspicious Parameters",
                10
            )

        return (
            count,
            found,
            "🔴 Many Suspicious Parameters",
            18
        )

    except Exception:
        return (
            0,
            [],
            "Not Checked",
            0
        )