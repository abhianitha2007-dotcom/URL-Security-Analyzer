import socket
import ssl

from datetime import datetime, timezone

from urllib.parse import urlparse




def extract_hostname(url):

    """
    Extract hostname from URL.
    """

    try:

        hostname = urlparse(url).hostname

        return hostname


    except Exception:

        return None





def parse_certificate_date(date_string):

    """
    Converts SSL certificate date.
    """

    try:

        return datetime.strptime(

            date_string,

            "%b %d %H:%M:%S %Y %Z"

        ).replace(

            tzinfo=timezone.utc

        )


    except Exception:

        return None





def get_ssl_info(url):

    """
    Retrieves SSL certificate information.

    Returns:
        dictionary
    """

    try:


        hostname = extract_hostname(url)



        if not hostname:


            raise Exception(
                "Invalid hostname"
            )




        context = ssl.create_default_context()



        with socket.create_connection(

            (hostname, 443),

            timeout=5

        ) as sock:



            with context.wrap_socket(

                sock,

                server_hostname=hostname

            ) as secure_socket:



                certificate = (
                    secure_socket
                    .getpeercert()
                )





        issuer = "Unknown"



        if "issuer" in certificate:


            issuer_data = dict(

                item[0]

                for item in certificate["issuer"]

            )


            issuer = (

                issuer_data.get(
                    "organizationName"
                )

                or "Unknown"

            )





        valid_from = parse_certificate_date(

            certificate.get(
                "notBefore"
            )

        )



        valid_to = parse_certificate_date(

            certificate.get(
                "notAfter"
            )

        )





        if valid_to:


            days_remaining = (

                valid_to

                -

                datetime.now(
                    timezone.utc
                )

            ).days


        else:


            days_remaining = "-"





        if days_remaining == "-":


            status = (
                "⚠️ Certificate date unavailable"
            )


        elif days_remaining >= 0:


            status = (
                "✅ Valid Certificate"
            )


        else:


            status = (
                "❌ Expired Certificate"
            )





        return {


            "issuer":
            issuer,



            "valid_from":

            valid_from.strftime(
                "%d-%m-%Y"
            )

            if valid_from

            else "Unknown",




            "valid_to":

            valid_to.strftime(
                "%d-%m-%Y"
            )

            if valid_to

            else "Unknown",




            "days_remaining":

            days_remaining,




            "status":

            status

        }





    except Exception:


        return {


            "issuer":
            "Unknown",



            "valid_from":
            "Unknown",



            "valid_to":
            "Unknown",



            "days_remaining":
            "-",



            "status":
            "Could not retrieve SSL certificate"

        }