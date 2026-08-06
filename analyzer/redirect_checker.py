import requests


MAX_REDIRECTS = 10


def check_redirects(url):

    """
    Returns

        redirect_count,
        final_url,
        status,
        score

    """

    try:

        response = requests.get(

            url,

            timeout=8,

            allow_redirects=True,

            headers={

                "User-Agent":

                "Mozilla/5.0"

            }

        )

        history = response.history

        redirect_count = len(history)

        final_url = response.url

        if redirect_count == 0:

            return (

                0,

                final_url,

                "🟢 No Redirect",

                0

            )

        if redirect_count == 1:

            return (

                1,

                final_url,

                "🟢 One Normal Redirect",

                0

            )

        if redirect_count <= 3:

            return (

                redirect_count,

                final_url,

                "🟡 Multiple Redirects",

                5

            )

        return (

            redirect_count,

            final_url,

            "🔴 Excessive Redirects",

            20

        )

    except Exception:

        return (

            0,

            url,

            "Not Checked",

            0

        )