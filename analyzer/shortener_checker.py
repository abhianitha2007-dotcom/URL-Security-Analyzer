from urllib.parse import urlparse



SHORTENERS = {

    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
    "lnkd.in",
    "trib.al",
    "shorte.st",
    "adf.ly",
    "tiny.one",
    "t.ly",
    "s.id",
    "v.gd",
    "clck.ru"

}




def check_shortener(url):
    """
    Detects known URL shortening services.

    Returns:

        found
        status
        score

    """

    try:


        hostname = urlparse(url).hostname



        if not hostname:


            return (

                False,

                "Not Checked",

                0

            )




        hostname = hostname.lower()



        # Remove www

        if hostname.startswith("www."):

            hostname = hostname[4:]





        if hostname in SHORTENERS:


            return (

                True,

                f"⚠️ URL Shortener Detected ({hostname})",

                20

            )





        return (

            False,

            "✅ No URL Shortener",

            0

        )





    except Exception:


        return (

            False,

            "Not Checked",

            0

        )