from urllib.parse import urlparse


def check_url_length(url):

    """
    Returns

        length,
        category,
        score

    """

    try:

        if not url:

            return (

                0,

                "Unknown",

                0

            )

        length = len(url)

        parsed = urlparse(url)

        path_length = len(parsed.path)

        query_length = len(parsed.query)

        # -----------------------------
        # Short URL
        # -----------------------------

        if length <= 75:

            return (

                length,

                "🟢 Short",

                0

            )

        # -----------------------------
        # Normal URL
        # -----------------------------

        if length <= 120:

            return (

                length,

                "🟡 Normal",

                5

            )

        # -----------------------------
        # Long URL
        # -----------------------------

        if length <= 180:

            return (

                length,

                "🟠 Long",

                12

            )

        # -----------------------------
        # Very Long URL
        # -----------------------------

        score = 20

        # Extra penalty for extremely long paths

        if path_length > 100:

            score += 5

        # Extra penalty for very long query strings

        if query_length > 80:

            score += 5

        return (

            length,

            "🔴 Very Long",

            score

        )

    except Exception:

        return (

            0,

            "Unknown",

            0

        )