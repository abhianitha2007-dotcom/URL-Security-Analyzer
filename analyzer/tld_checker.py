from urllib.parse import urlparse



# TLDs frequently abused in phishing campaigns

HIGH_RISK_TLDS = {

    "tk",
    "ml",
    "ga",
    "cf",
    "gq",

    "top",
    "click",
    "zip",
    "country",
    "stream"

}



# TLDs that need moderate attention

MEDIUM_RISK_TLDS = {

    "xyz",
    "live",
    "buzz",
    "work",
    "support",
    "review",
    "shop"

}





def check_tld(url):
    """
    Checks domain TLD reputation.

    Returns:

        tld
        status
        score

    """

    try:


        hostname = urlparse(url).hostname



        if not hostname:


            return (

                "Unknown",

                "Not Checked",

                0

            )





        hostname = hostname.lower()



        parts = hostname.split(".")




        if len(parts) < 2:


            return (

                "Unknown",

                "Invalid Domain",

                0

            )





        tld = parts[-1]





        if tld in HIGH_RISK_TLDS:


            return (

                tld,

                f"🔴 High-Risk TLD (.{tld})",

                20

            )





        elif tld in MEDIUM_RISK_TLDS:


            return (

                tld,

                f"🟡 Medium-Risk TLD (.{tld})",

                10

            )





        else:


            return (

                tld,

                f"🟢 Common TLD (.{tld})",

                0

            )





    except Exception:


        return (

            "Unknown",

            "Not Checked",

            0

        )