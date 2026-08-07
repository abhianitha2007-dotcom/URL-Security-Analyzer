from urllib.parse import urlparse
import re


# Login / Authentication

LOGIN_KEYWORDS = {

    "login",
    "signin",
    "sign-in",
    "authenticate",
    "auth",
    "verify",
    "verification",
    "password",
    "credential",
    "otp",
    "2fa"

}


# Banking / Payment

BANKING_KEYWORDS = {

    "bank",
    "payment",
    "wallet",
    "invoice",
    "billing",
    "upi",
    "credit",
    "debit",
    "refund",
    "transaction"

}


# Account Related

ACCOUNT_KEYWORDS = {

    "account",
    "update",
    "confirm",
    "recovery",
    "recover",
    "unlock",
    "reset",
    "activate"

}


# Urgency / Threat

URGENCY_KEYWORDS = {

    "alert",
    "warning",
    "expired",
    "expire",
    "blocked",
    "suspended",
    "limited",
    "security"

}


# Cryptocurrency

CRYPTO_KEYWORDS = {

    "crypto",
    "bitcoin",
    "btc",
    "ethereum",
    "eth",
    "usdt"

}


SUSPICIOUS_KEYWORDS = (

    LOGIN_KEYWORDS
    | BANKING_KEYWORDS
    | ACCOUNT_KEYWORDS
    | URGENCY_KEYWORDS
    | CRYPTO_KEYWORDS

)


def check_keywords(url):

    """
    Returns

        keyword_count,
        matched_keywords

    """

    try:

        parsed = urlparse(url)

        text = " ".join([

            parsed.netloc,

            parsed.path,

            parsed.query

        ]).lower()

        found = []

        for keyword in sorted(SUSPICIOUS_KEYWORDS):

            pattern = rf"\b{re.escape(keyword)}\b"

            if re.search(pattern, text):

                found.append(keyword)

        return (

            len(found),

            found

        )

    except Exception:

        return (

            0,

            []

        )