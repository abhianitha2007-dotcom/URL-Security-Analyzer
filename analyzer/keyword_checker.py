from urllib.parse import urlparse
import re



# Common phishing-related keywords

SUSPICIOUS_KEYWORDS = [

    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "account",
    "password",
    "credential",
    "bank",
    "payment",
    "invoice",
    "wallet",
    "crypto",
    "recover",
    "unlock",
    "alert",
    "auth"

]





def check_keywords(url):
    """
    Detects suspicious words in URL.

    Checks:
    - domain
    - path
    - query parameters

    Returns:

        count
        matched keywords

    """

    try:


        parsed = urlparse(url)



        text = (

            parsed.netloc

            + " "

            + parsed.path

            + " "

            + parsed.query

        ).lower()




        found = []



        for keyword in SUSPICIOUS_KEYWORDS:



            # Match complete words

            pattern = (

                r"\b"

                + re.escape(keyword)

                + r"\b"

            )



            if re.search(
                pattern,
                text
            ):

                found.append(
                    keyword
                )





        return (

            len(found),

            found

        )





    except Exception:


        return (

            0,

            []

        )