from datetime import datetime

from analyzer.whois_service import (
    extract_domain,
    get_whois_data
)


# =========================================================
# CREATION DATE NORMALIZATION
# =========================================================

def get_creation_date(
    value
):
    """
    Normalize python-whois creation-date values.

    WHOIS libraries may return either:

        datetime

    or:

        list[datetime]
    """

    if isinstance(
        value,
        list
    ):

        if not value:

            return None


        value = value[0]


    if not isinstance(
        value,
        datetime
    ):

        return None


    if value.tzinfo:

        value = value.replace(
            tzinfo=None
        )


    return value


# =========================================================
# UNKNOWN RESULT
# =========================================================

def unknown_result(
    message
):
    """
    Standard domain-age result when the age cannot be
    verified.
    """

    return {

        "age":
            "Unknown",

        "risk":
            False,

        "confirmed_new":
            False,

        "message":
            message
    }


# =========================================================
# DOMAIN AGE CHECK
# =========================================================

def check_domain_age(
    url
):
    """
    Analyze domain registration age.

    WHOIS data is obtained through the shared WHOIS service,
    so the WHOIS information checker can reuse the same
    lookup instead of performing another network request.

    Returns:

        {
            age,
            risk,
            confirmed_new,
            message
        }
    """

    try:

        domain = extract_domain(
            url
        )


        if not domain:

            return unknown_result(
                "Invalid domain."
            )


        # -------------------------------------------------
        # SHARED WHOIS LOOKUP
        # -------------------------------------------------

        data = get_whois_data(
            url
        )


        if data is None:

            return unknown_result(
                "WHOIS lookup failed."
            )


        # -------------------------------------------------
        # CREATION DATE
        # -------------------------------------------------

        creation_date = (
            get_creation_date(
                getattr(
                    data,
                    "creation_date",
                    None
                )
            )
        )


        if not creation_date:

            return unknown_result(
                "Domain age could not be verified."
            )


        # -------------------------------------------------
        # AGE CALCULATION
        # -------------------------------------------------

        age_days = (
            datetime.now()
            - creation_date
        ).days


        # Defensive protection against malformed future
        # WHOIS dates.
        if age_days < 0:

            return unknown_result(
                "Domain age could not be verified."
            )


        age_years = round(
            age_days / 365.25,
            1
        )


        # =================================================
        # UNDER 30 DAYS
        # =================================================

        if age_days < 30:

            return {

                "age":
                    f"{age_days} days",

                "risk":
                    True,

                "confirmed_new":
                    True,

                "message":
                    (
                        "🔴 Domain registered within "
                        "the last 30 days."
                    )
            }


        # =================================================
        # UNDER 180 DAYS
        # =================================================

        if age_days < 180:

            return {

                "age":
                    f"{age_days} days",

                "risk":
                    True,

                "confirmed_new":
                    True,

                "message":
                    "🟠 Very new domain."
            }


        # =================================================
        # UNDER ONE YEAR
        # =================================================

        if age_days < 365:

            return {

                "age":
                    f"{age_days} days",

                "risk":
                    True,

                "confirmed_new":
                    True,

                "message":
                    (
                        "🟡 Domain is less than "
                        "one year old."
                    )
            }


        # =================================================
        # 1 - 3 YEARS
        # =================================================

        if age_days < 1095:

            return {

                "age":
                    f"{age_years} years",

                "risk":
                    False,

                "confirmed_new":
                    False,

                "message":
                    "🟢 Established domain."
            }


        # =================================================
        # 3+ YEARS
        # =================================================

        return {

            "age":
                f"{age_years} years",

            "risk":
                False,

            "confirmed_new":
                False,

            "message":
                "✅ Well-established domain."
        }


    except Exception:

        return unknown_result(
            "WHOIS lookup failed."
        )