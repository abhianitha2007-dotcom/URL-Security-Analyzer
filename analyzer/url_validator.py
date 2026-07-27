from urllib.parse import urlparse
import re



def is_valid_url(url):
    """
    Validates URL structure.

    Checks:
    - HTTP/HTTPS scheme
    - hostname exists
    - no spaces
    - valid hostname format
    - domain structure

    Returns:
        True / False
    """

    try:

        # Empty URL

        if not url:

            return False



        # Spaces are not allowed

        if " " in url:

            return False




        parsed = urlparse(url)




        # Check protocol

        if parsed.scheme not in (
            "http",
            "https"
        ):

            return False




        # Check hostname

        hostname = parsed.hostname


        if not hostname:

            return False




        hostname = hostname.lower()




        # Remove www

        if hostname.startswith(
            "www."
        ):

            hostname = hostname[4:]





        # Minimum hostname length

        if len(hostname) < 3:

            return False





        # Allow IP addresses
        # They will be handled
        # by ip_checker.py



        # Domain validation

        domain_pattern = re.compile(

            r"^[a-z0-9.-]+$"

        )



        if not domain_pattern.match(
            hostname
        ):

            return False





        # Normal domains require dot

        # Example:
        # google.com

        if "." not in hostname:


            return False





        # Prevent invalid dots

        if hostname.startswith(".") or hostname.endswith("."):


            return False




        return True




    except Exception:


        return False