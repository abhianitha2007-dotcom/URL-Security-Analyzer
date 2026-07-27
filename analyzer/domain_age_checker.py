from datetime import datetime

from urllib.parse import urlparse

import whois




def extract_domain(url):

    """
    Extract clean domain name.
    """

    parsed = urlparse(url)

    hostname = parsed.hostname


    if hostname is None:

        return None


    # Remove www prefix

    if hostname.startswith("www."):

        hostname = hostname[4:]


    return hostname





def get_creation_date(value):

    """
    Handles different WHOIS date formats.
    """

    if isinstance(value, list):

        value = value[0]


    if value is None:

        return None


    if not isinstance(value, datetime):

        return None


    # Remove timezone

    if value.tzinfo:

        value = value.replace(
            tzinfo=None
        )


    return value





def check_domain_age(url):

    """
    Checks domain age using WHOIS.

    Returns:

    {
        age,
        risk,
        message
    }

    """


    try:


        domain = extract_domain(url)


        if not domain:


            return {

                "age": "Unknown",

                "risk": True,

                "message":
                "Invalid domain."

            }



        data = whois.whois(domain)



        creation_date = get_creation_date(

            data.creation_date

        )



        if not creation_date:


            return {

                "age": "Unknown",

                "risk": True,

                "message":
                "Could not determine domain age."

            }




        age_days = (

            datetime.now()

            - creation_date

        ).days




        if age_days < 180:


            return {

                "age":
                f"{age_days} days",


                "risk": True,


                "message":
                "⚠️ Very new domain."

            }



        elif age_days < 365:


            return {

                "age":
                f"{age_days} days",


                "risk": True,


                "message":
                "⚠️ Domain is less than one year old."

            }




        else:


            return {

                "age":
                f"{age_days} days",


                "risk": False,


                "message":
                "✅ Old domain."

            }




    except Exception:


        return {

            "age":
            "Unknown",


            "risk":
            True,


            "message":
            "WHOIS lookup failed."

        }