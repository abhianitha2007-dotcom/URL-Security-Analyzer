from analyzer.whois_service import (
    extract_domain,
    get_whois_data
)


# =========================================================
# DATE FORMATTING
# =========================================================

def format_date(
    value
):
    """
    Format a WHOIS date for display.
    """

    try:

        if isinstance(
            value,
            list
        ):

            if not value:

                return "Unknown"


            value = value[0]


        if value is None:

            return "Unknown"


        return value.strftime(
            "%d-%m-%Y"
        )


    except Exception:

        return "Unknown"


# =========================================================
# LIST FORMATTING
# =========================================================

def format_list(
    value
):
    """
    Format WHOIS list-like values for display.
    """

    try:

        if isinstance(
            value,
            (
                list,
                tuple,
                set
            )
        ):

            unique = sorted(
                set(
                    str(item)
                    for item in value
                    if item
                )
            )


            if not unique:

                return "Unknown"


            return ", ".join(
                unique
            )


        if value:

            return str(
                value
            )


        return "Unknown"


    except Exception:

        return "Unknown"


# =========================================================
# DEFAULT RESULT
# =========================================================

def unknown_whois_result():
    """
    Return a consistent WHOIS result when information
    cannot be obtained.
    """

    return {

        "registrar":
            "Unknown",

        "creation_date":
            "Unknown",

        "expiration_date":
            "Unknown",

        "updated_date":
            "Unknown",

        "organization":
            "Unknown",

        "country":
            "Unknown",

        "status":
            "Unknown",

        "name_servers":
            "Unknown"
    }


# =========================================================
# WHOIS INFORMATION
# =========================================================

def get_whois_info(
    url
):
    """
    Return formatted WHOIS information.

    Raw WHOIS information comes from the shared WHOIS
    service.

    If check_domain_age() already performed the lookup,
    this function receives the cached information and does
    not perform another WHOIS network request.

    Returns:

        {
            registrar,
            creation_date,
            expiration_date,
            updated_date,
            organization,
            country,
            status,
            name_servers
        }
    """

    try:

        domain = extract_domain(
            url
        )


        if not domain:

            return (
                unknown_whois_result()
            )


        # -------------------------------------------------
        # SHARED WHOIS LOOKUP
        # -------------------------------------------------

        data = get_whois_data(
            url
        )


        if data is None:

            return (
                unknown_whois_result()
            )


        # -------------------------------------------------
        # FORMAT RESULT
        # -------------------------------------------------

        return {

            "registrar":

                getattr(
                    data,
                    "registrar",
                    None
                )
                or "Unknown",


            "creation_date":

                format_date(
                    getattr(
                        data,
                        "creation_date",
                        None
                    )
                ),


            "expiration_date":

                format_date(
                    getattr(
                        data,
                        "expiration_date",
                        None
                    )
                ),


            "updated_date":

                format_date(
                    getattr(
                        data,
                        "updated_date",
                        None
                    )
                ),


            "organization":

                getattr(
                    data,
                    "org",
                    None
                )

                or getattr(
                    data,
                    "organization",
                    None
                )

                or "Unknown",


            "country":

                getattr(
                    data,
                    "country",
                    None
                )

                or "Unknown",


            "status":

                format_list(
                    getattr(
                        data,
                        "status",
                        None
                    )
                ),


            "name_servers":

                format_list(
                    getattr(
                        data,
                        "name_servers",
                        None
                    )
                )
        }


    except Exception:

        return (
            unknown_whois_result()
        )