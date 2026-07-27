from urllib.parse import urlparse

import whois



def extract_domain(url):

    """
    Extract domain from URL.
    """

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname


        if hostname is None:

            return None


        if hostname.startswith("www."):

            hostname = hostname[4:]


        return hostname


    except Exception:

        return None




def format_date(value):

    """
    Converts WHOIS dates into readable format.
    """

    try:

        if isinstance(value, list):

            value = value[0]


        if value is None:

            return "Unknown"


        return value.strftime(
            "%d-%m-%Y"
        )


    except Exception:

        return "Unknown"




def format_nameservers(value):

    """
    Formats name servers.
    """

    try:

        if isinstance(value, list):

            value = list(
                set(value)
            )

            return ", ".join(
                sorted(value)
            )


        if value:

            return str(value)


        return "Unknown"


    except Exception:

        return "Unknown"





def get_whois_info(url):

    """
    Retrieves WHOIS information.

    Returns:
        dictionary
    """

    try:


        domain = extract_domain(url)



        if not domain:


            return {

                "registrar": "Unknown",

                "creation_date": "Unknown",

                "expiration_date": "Unknown",

                "updated_date": "Unknown",

                "name_servers": "Unknown"

            }



        data = whois.whois(domain)




        return {


            "registrar":
            data.registrar
            or "Unknown",



            "creation_date":
            format_date(
                data.creation_date
            ),



            "expiration_date":
            format_date(
                data.expiration_date
            ),



            "updated_date":
            format_date(
                data.updated_date
            ),



            "name_servers":
            format_nameservers(
                data.name_servers
            )


        }




    except Exception:


        return {


            "registrar":
            "Unknown",



            "creation_date":
            "Unknown",



            "expiration_date":
            "Unknown",



            "updated_date":
            "Unknown",



            "name_servers":
            "Unknown"

        }