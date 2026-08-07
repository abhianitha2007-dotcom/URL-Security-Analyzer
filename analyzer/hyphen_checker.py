from urllib.parse import urlparse



def check_hyphen(url):
    """
    Detects hyphens in domain name.

    Returns:

        hyphen_count
        status
        score

    """

    try:


        hostname = urlparse(url).hostname



        if not hostname:


            return (

                0,

                "Not Checked",

                0

            )




        hostname = hostname.lower()




        # Remove www

        if hostname.startswith("www."):

            hostname = hostname[4:]





        # Check only main domain

        domain_parts = hostname.split(".")



        if len(domain_parts) >= 2:

            domain_name = domain_parts[-2]


        else:

            domain_name = hostname





        hyphen_count = domain_name.count("-")





        if hyphen_count == 0:


            return (

                0,

                "✅ No Hyphens",

                0

            )



        elif hyphen_count == 1:


            return (

                1,

                "🟡 One Hyphen",

                5

            )



        elif hyphen_count <= 3:


            return (

                hyphen_count,

                "⚠️ Multiple Hyphens",

                15

            )



        else:


            return (

                hyphen_count,

                "🚨 Excessive Hyphens",

                25

            )





    except Exception:


        return (

            0,

            "Not Checked",

            0

        )