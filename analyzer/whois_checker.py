import whois


def get_whois_info(url):
    """
    Retrieves WHOIS information for a domain.

    Returns:
        dict
    """

    try:
        domain = (
            url.replace("https://", "")
               .replace("http://", "")
               .split("/")[0]
        )

        w = whois.whois(domain)

        def format_date(value):
            if isinstance(value, list):
                value = value[0]

            if value is None:
                return "Unknown"

            return value.strftime("%d-%m-%Y")

        registrar = w.registrar or "Unknown"

        creation_date = format_date(w.creation_date)

        expiration_date = format_date(w.expiration_date)

        updated_date = format_date(w.updated_date)

        name_servers = w.name_servers

        if isinstance(name_servers, list):
            name_servers = ", ".join(sorted(set(name_servers)))

        if not name_servers:
            name_servers = "Unknown"

        return {
            "registrar": registrar,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "updated_date": updated_date,
            "name_servers": name_servers,
        }

    except Exception:

        return {
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "updated_date": "Unknown",
            "name_servers": "Unknown",
        }