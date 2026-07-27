def check_url_length(url):
    """
    Checks URL length.

    Returns:

        length
        category
        risk_score

    """

    try:

        if not url:

            return (
                0,
                "Unknown",
                0
            )



        length = len(url)



        # Normal URL

        if length <= 60:

            return (

                length,

                "🟢 Short",

                0

            )



        # Slightly long URL

        elif length <= 100:

            return (

                length,

                "🟡 Medium",

                10

            )



        # Very long URL

        else:

            return (

                length,

                "🔴 Long",

                20

            )



    except Exception:


        return (

            0,

            "Unknown",

            0

        )