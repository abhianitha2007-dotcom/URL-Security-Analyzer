from urllib.parse import urlparse



def check_at_symbol(url):
    """
    Detects '@' symbol misuse in URLs.

    Returns:

        found
        status
        score

    """

    try:

        parsed = urlparse(url)



        # URL username field exists
        # when @ is used before hostname

        if parsed.username is not None:


            return (

                True,

                "⚠️ '@' Symbol Detected",

                25

            )



        return (

            False,

            "✅ No '@' Symbol",

            0

        )



    except Exception:


        return (

            False,

            "Not Checked",

            0

        )