import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime


def get_ssl_info(url):
    """
    Retrieves SSL certificate information.

    Returns:
        dict
    """

    try:

        hostname = urlparse(url).hostname

        if hostname is None:
            raise Exception()

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_sock:

                cert = secure_sock.getpeercert()

        issuer = dict(x[0] for x in cert["issuer"])

        issuer_name = issuer.get("organizationName", "Unknown")

        valid_from = datetime.strptime(
            cert["notBefore"],
            "%b %d %H:%M:%S %Y %Z"
        )

        valid_to = datetime.strptime(
            cert["notAfter"],
            "%b %d %H:%M:%S %Y %Z"
        )

        days_remaining = (valid_to - datetime.utcnow()).days

        status = (
            "✅ Valid Certificate"
            if days_remaining >= 0
            else "❌ Expired Certificate"
        )

        return {

            "issuer": issuer_name,

            "valid_from":
                valid_from.strftime("%d-%m-%Y"),

            "valid_to":
                valid_to.strftime("%d-%m-%Y"),

            "days_remaining":
                days_remaining,

            "status":
                status

        }

    except Exception:

        return {

            "issuer": "Unknown",

            "valid_from": "Unknown",

            "valid_to": "Unknown",

            "days_remaining": "-",

            "status": "Could not retrieve SSL certificate"

        }