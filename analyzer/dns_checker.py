import dns.resolver

from urllib.parse import urlparse



DNS_RECORD_TYPES = [

    "A",
    "AAAA",
    "MX",
    "NS",
    "CNAME"

]




def get_hostname(url):

    """
    Extract hostname from URL.
    """

    try:

        hostname = urlparse(url).hostname


        if hostname:

            return hostname.lower()


        return None


    except Exception:

        return None





def get_dns_records(url):

    """
    Retrieves DNS records.

    Returns:

    {
        A: [],
        AAAA: [],
        MX: [],
        NS: [],
        CNAME: []
    }

    """


    records = {

        record_type: []

        for record_type in DNS_RECORD_TYPES

    }



    try:


        hostname = get_hostname(url)



        if not hostname:

            return records




        resolver = dns.resolver.Resolver()


        # Prevent long waiting times

        resolver.timeout = 3

        resolver.lifetime = 5




        for record_type in DNS_RECORD_TYPES:


            try:


                answers = resolver.resolve(

                    hostname,

                    record_type

                )



                for answer in answers:

                    records[record_type].append(

                        str(answer)

                    )



            except (

                dns.resolver.NoAnswer,

                dns.resolver.NXDOMAIN,

                dns.resolver.Timeout

            ):

                continue



            except Exception:

                continue





        return records





    except Exception:


        return records