from urllib.parse import urlparse



# Common multi-level TLDs

MULTI_LEVEL_TLDS = {

    "co.uk",
    "org.uk",
    "gov.uk",

    "co.in",
    "firm.in",
    "net.in",

    "com.au",
    "net.au",

    "co.jp"

}





def get_domain_parts(hostname):

    """
    Removes TLD correctly.
    """

    parts = hostname.split(".")


    if len(parts) < 2:

        return parts



    last_two = ".".join(
        parts[-2:]
    )


    if last_two in MULTI_LEVEL_TLDS:

        return parts[:-2]



    return parts[:-1]





def count_subdomains(url):
    """
    Counts URL subdomains.

    Returns:

        count
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




        domain_parts = get_domain_parts(
            hostname
        )



        subdomain_count = len(
            domain_parts
        ) - 1




        if subdomain_count <= 0:


            return (

                0,

                "🟢 Normal",

                0

            )



        elif subdomain_count == 1:


            return (

                1,

                "🟢 One Subdomain",

                5

            )



        elif subdomain_count == 2:


            return (

                2,

                "🟡 Multiple Subdomains",

                15

            )



        else:


            return (

                subdomain_count,

                "🔴 Too Many Subdomains",

                30

            )



    except Exception:


        return (

            0,

            "Not Checked",

            0

        )