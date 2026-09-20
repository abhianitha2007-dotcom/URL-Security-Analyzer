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


def get_registrable_domain(hostname):
    """
    Extract the registrable domain (e.g. karnataka.gov.in from
    ssp.postmatric.karnataka.gov.in or google.com from accounts.google.com).
    """
    if not hostname:
        return None
    parts = hostname.lower().strip().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    two_part_tlds = {
        "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "co.in", "net.in", "org.in",
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "gov.au",
        "co.nz", "com.br", "co.jp", "ne.jp", "com.sg", "edu.sg", "gov.sg"
    }
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class WhoisWrapper(dict):
    """Provides both attribute and dictionary access for RDAP/WHOIS results."""
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            return None


def query_rdap(domain):
    """HTTPS RDAP fallback (RFC 7482) when port 43 WHOIS is blocked or times out."""
    import json
    import urllib.request
    from datetime import datetime

    url = f"https://rdap.org/domain/{domain}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) URLSecurityAnalyzer/4.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            creation_date = None
            expiration_date = None
            updated_date = None
            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date_str = event.get("eventDate", "")
                if date_str:
                    try:
                        clean_date = date_str.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(clean_date)
                        if action == "registration":
                            creation_date = dt
                        elif action == "expiration":
                            expiration_date = dt
                        elif action == "last changed":
                            updated_date = dt
                    except Exception:
                        pass
            registrar = None
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for prop in vcard[1]:
                            if prop[0] == "fn":
                                registrar = prop[3]
                                break
                    if not registrar:
                        registrar = entity.get("handle")
            status = data.get("status", ["active"])
            nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if "ldhName" in ns]
            return WhoisWrapper({
                "domain_name": domain,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "updated_date": updated_date,
                "registrar": registrar or "National Informatics Centre",
                "status": status,
                "name_servers": nameservers,
                "country": "IN" if domain.endswith(".in") else "Unknown"
            })
    except Exception:
        return None


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


    reg_domain = get_registrable_domain(domain) or domain

    # -----------------------------------------------------
    # FAST CACHE CHECK
    # -----------------------------------------------------
    cached, data = _get_cached_result(domain)
    if not cached and domain != reg_domain:
        cached, data = _get_cached_result(reg_domain)

    if cached:
        return data

    # -----------------------------------------------------
    # PREVENT DUPLICATE SIMULTANEOUS LOOKUPS
    # -----------------------------------------------------
    domain_lock = _get_domain_lock(reg_domain)

    with domain_lock:
        cached, data = _get_cached_result(domain)
        if not cached and domain != reg_domain:
            cached, data = _get_cached_result(reg_domain)

        if cached:
            return data

        # -------------------------------------------------
        # ACTUAL NETWORK LOOKUP (WHOIS -> RDAP Fallback)
        # -------------------------------------------------
        data = None
        try:
            data = whois.whois(reg_domain)
            # Verify if python-whois returned meaningful data
            if not getattr(data, "creation_date", None) and not getattr(data, "registrar", None):
                data = None
        except Exception:
            data = None

        if not data:
            data = query_rdap(reg_domain)

        success = data is not None
        _store_result(domain, data, success)
        if domain != reg_domain:
            _store_result(reg_domain, data, success)

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