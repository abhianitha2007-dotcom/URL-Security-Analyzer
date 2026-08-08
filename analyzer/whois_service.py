import threading
import time

from urllib.parse import urlparse

import whois


# =========================================================
# SHARED WHOIS LOOKUP SERVICE
# =========================================================

# Successful WHOIS information changes extremely slowly.
# Keeping it for five minutes is more than safe for a scan
# and also speeds up repeated scans of the same domain.
WHOIS_CACHE_TTL = 300


# Failed WHOIS requests are cached only briefly.
#
# This prevents both domain_age_checker and whois_checker
# from waiting on the same failing lookup during one scan,
# while still allowing a retry later.
WHOIS_FAILURE_TTL = 30


_cache = {}
_cache_lock = threading.Lock()

_domain_locks = {}
_domain_locks_lock = threading.Lock()


# =========================================================
# DOMAIN EXTRACTION
# =========================================================

def extract_domain(url):
    """
    Extract and normalize the hostname used for WHOIS.

    Returns:
        str | None
    """

    try:

        hostname = urlparse(
            url
        ).hostname

    except Exception:

        return None


    if not hostname:

        return None


    hostname = (
        hostname
        .lower()
        .strip()
        .rstrip(".")
    )


    if hostname.startswith(
        "www."
    ):

        hostname = hostname[4:]


    return hostname or None


# =========================================================
# DOMAIN LOCK
# =========================================================

def _get_domain_lock(
    domain
):
    """
    Return a dedicated lock for a domain.

    This prevents two analyzers running at the same time
    from performing duplicate WHOIS requests for the same
    domain.
    """

    with _domain_locks_lock:

        lock = _domain_locks.get(
            domain
        )


        if lock is None:

            lock = threading.Lock()

            _domain_locks[
                domain
            ] = lock


        return lock


# =========================================================
# CACHE LOOKUP
# =========================================================

def _get_cached_result(
    domain
):
    """
    Return:

        (found, value)

    found=False means there is no usable cached entry.

    value may legitimately be None when a recent WHOIS
    lookup failed.
    """

    current_time = (
        time.monotonic()
    )


    with _cache_lock:

        entry = _cache.get(
            domain
        )


        if entry is None:

            return (
                False,
                None
            )


        cached_at = entry[
            "cached_at"
        ]

        success = entry[
            "success"
        ]

        ttl = (
            WHOIS_CACHE_TTL
            if success
            else WHOIS_FAILURE_TTL
        )


        if (
            current_time
            - cached_at
            > ttl
        ):

            _cache.pop(
                domain,
                None
            )

            return (
                False,
                None
            )


        return (
            True,
            entry["data"]
        )


# =========================================================
# CACHE STORAGE
# =========================================================

def _store_result(
    domain,
    data,
    success
):
    """
    Store a WHOIS result in the in-memory cache.
    """

    with _cache_lock:

        _cache[
            domain
        ] = {

            "cached_at":
                time.monotonic(),

            "success":
                bool(success),

            "data":
                data
        }


# =========================================================
# WHOIS LOOKUP
# =========================================================

def get_whois_data(
    url
):
    """
    Return raw python-whois information for a URL.

    During one scan, both:

        domain_age_checker
        whois_checker

    can call this function.

    Only the first call performs the actual network WHOIS
    lookup. The second receives the cached result.

    Returns:
        python-whois result object

        or

        None
            Invalid domain or WHOIS lookup failure.
    """

    domain = extract_domain(
        url
    )


    if not domain:

        return None


    # -----------------------------------------------------
    # FAST CACHE CHECK
    # -----------------------------------------------------

    (
        cached,
        data
    ) = _get_cached_result(
        domain
    )


    if cached:

        return data


    # -----------------------------------------------------
    # PREVENT DUPLICATE SIMULTANEOUS LOOKUPS
    # -----------------------------------------------------

    domain_lock = (
        _get_domain_lock(
            domain
        )
    )


    with domain_lock:

        # -------------------------------------------------
        # Another thread may have completed the lookup
        # while this thread was waiting for the lock.
        # -------------------------------------------------

        (
            cached,
            data
        ) = _get_cached_result(
            domain
        )


        if cached:

            return data


        # -------------------------------------------------
        # ACTUAL NETWORK WHOIS LOOKUP
        # -------------------------------------------------

        try:

            data = whois.whois(
                domain
            )

        except Exception:

            _store_result(
                domain,
                None,
                False
            )

            return None


        # -------------------------------------------------
        # CACHE SUCCESSFUL RESULT
        # -------------------------------------------------

        _store_result(
            domain,
            data,
            True
        )


        return data


# =========================================================
# CACHE CLEANUP
# =========================================================

def clear_whois_cache():
    """
    Clear cached WHOIS information.

    Mainly useful for testing or diagnostics.
    """

    with _cache_lock:

        _cache.clear()