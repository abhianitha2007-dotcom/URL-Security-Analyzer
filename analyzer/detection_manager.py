from analyzer.https_checker import check_https
from analyzer.ip_checker import contains_ip
from analyzer.keyword_checker import check_keywords
from analyzer.length_checker import check_url_length
from analyzer.subdomain_checker import count_subdomains
from analyzer.at_symbol_checker import check_at_symbol
from analyzer.shortener_checker import check_shortener
from analyzer.hyphen_checker import check_hyphen

from analyzer.domain_age_checker import check_domain_age
from analyzer.whois_checker import get_whois_info
from analyzer.dns_checker import get_dns_records
from analyzer.ssl_checker import get_ssl_info
from analyzer.tld_checker import check_tld

from analyzer.entropy_checker import check_entropy
from analyzer.redirect_checker import check_redirects
from analyzer.port_checker import check_port
from analyzer.query_checker import check_query_parameters

from analyzer.homograph_checker import check_homograph
from analyzer.typosquatting_checker import check_typosquatting
from analyzer.punycode_checker import check_punycode
from analyzer.domain_similarity_checker import check_domain_similarity

from analyzer.javascript_checker import check_javascript
from analyzer.security_headers_checker import check_security_headers
from analyzer.form_checker import check_forms
from analyzer.content_checker import check_content
from analyzer.favicon_checker import check_favicon

from analyzer.file_extension_checker import check_file_extension
from analyzer.email_checker import check_email_address

from analyzer.robots_checker import check_robots
from analyzer.sitemap_checker import check_sitemap
from analyzer.response_header_checker import check_response_headers
from analyzer.technology_checker import check_technology
from analyzer.file_exposure_checker import check_file_exposure
from analyzer.http_methods_checker import check_http_methods

from analyzer.cookie_security_checker import check_cookie_security
from analyzer.cors_checker import check_cors_security
from analyzer.mixed_content_checker import check_mixed_content

from analyzer.threat_intelligence_checker import (
    check_threat_intelligence
)


# =========================================================
# HELPERS
# =========================================================

def safe_int(value, default=0):
    """
    Convert a value to int safely.
    """

    try:
        return int(value or default)

    except (
        TypeError,
        ValueError
    ):
        return default


# =========================================================
# MAIN DETECTION MANAGER
# =========================================================

def run_all_checks(url):
    """
    Run all URL Security Analyzer detection modules.

    Returns:
        dict containing all detection results.

    This function only coordinates analyzers.

    Final risk calculation is handled separately
    by risk_engine.py.
    """

    # =====================================================
    # 1. BASIC URL STRUCTURE
    # =====================================================

    https = check_https(url)

    ip_found = contains_ip(url)


    keyword_count, keywords = (
        check_keywords(url)
    )


    (
        url_length,
        length_status,
        length_score
    ) = check_url_length(url)


    (
        subdomain_count,
        subdomain_status,
        subdomain_score
    ) = count_subdomains(url)


    (
        at_found,
        at_status,
        at_score
    ) = check_at_symbol(url)


    (
        shortener_found,
        shortener_status,
        shortener_score
    ) = check_shortener(url)


    (
        hyphen_count,
        hyphen_status,
        hyphen_score
    ) = check_hyphen(url)


    (
        port,
        port_status,
        port_score
    ) = check_port(url)


    (
        query_count,
        suspicious_parameters,
        query_status,
        query_score
    ) = check_query_parameters(url)


    (
        file_extension,
        file_status,
        file_score
    ) = check_file_extension(url)


    (
        detected_emails,
        email_status,
        email_score
    ) = check_email_address(url)


    # =====================================================
    # 2. DOMAIN IDENTITY
    # =====================================================

    (
        tld,
        tld_status,
        tld_score
    ) = check_tld(url)


    (
        entropy,
        entropy_status,
        entropy_score
    ) = check_entropy(url)


    (
        homograph_found,
        homograph_status,
        homograph_score
    ) = check_homograph(url)


    (
        typosquatting_found,
        typosquatting_status,
        typosquatting_score
    ) = check_typosquatting(url)


    (
        punycode_found,
        punycode_status,
        punycode_score
    ) = check_punycode(url)


    (
        similar_words,
        similarity_status,
        similarity_score
    ) = check_domain_similarity(url)


    # =====================================================
    # 3. DOMAIN / NETWORK INFRASTRUCTURE
    # =====================================================

    domain_age = (
        check_domain_age(url)
        or {}
    )


    whois_info = (
        get_whois_info(url)
        or {}
    )


    dns_records = (
        get_dns_records(url)
        or {}
    )


    ssl_info = (
        get_ssl_info(url)
        or {}
    )


    # -----------------------------------------------------
    # Preserve the domain-age checker's own score.
    #
    # Only use the previous 20-point fallback if the
    # checker reports confirmed_new but provides no score.
    # -----------------------------------------------------

    domain_age_score = safe_int(
        domain_age.get(
            "score",
            0
        )
    )


    if (
        domain_age_score == 0
        and domain_age.get(
            "confirmed_new",
            False
        )
    ):
        domain_age_score = 20


    # =====================================================
    # 4. REDIRECT / PAGE BEHAVIOUR
    # =====================================================

    (
        redirect_count,
        final_url,
        redirect_status,
        redirect_score
    ) = check_redirects(url)


    (
        javascript_patterns,
        javascript_status,
        javascript_score
    ) = check_javascript(url)


    (
        form_issues,
        form_status,
        form_score
    ) = check_forms(url)


    (
        content_patterns,
        content_status,
        content_score
    ) = check_content(url)


    (
        favicon_url,
        favicon_status,
        favicon_score
    ) = check_favicon(url)


    # =====================================================
    # 5. SECURITY HEADERS
    # =====================================================

    (
        missing_headers,
        headers_status,
        headers_score
    ) = check_security_headers(url)


    response_headers = (
        check_response_headers(url)
        or {}
    )


    # =====================================================
    # 6. WEBSITE DISCOVERY
    # =====================================================

    robots = (
        check_robots(url)
        or {}
    )


    # Sitemap checker can reuse sitemap locations found
    # inside robots.txt.

    sitemap = (
        check_sitemap(
            url,
            discovered_sitemaps=robots.get(
                "sitemap_urls",
                []
            )
        )
        or {}
    )


    # =====================================================
    # 7. SERVER / TECHNOLOGY SECURITY
    # =====================================================

    technology = (
        check_technology(url)
        or {}
    )


    file_exposure = (
        check_file_exposure(url)
        or {}
    )


    http_methods = (
        check_http_methods(url)
        or {}
    )


    # =====================================================
    # 8. ADDITIONAL WEB SECURITY
    # =====================================================

    cookie_security = (
        check_cookie_security(url)
        or {}
    )


    cors = (
        check_cors_security(url)
        or {}
    )


    mixed_content = (
        check_mixed_content(url)
        or {}
    )


    # =====================================================
    # 9. EXTERNAL THREAT INTELLIGENCE
    # =====================================================

    threat_intelligence = (
        check_threat_intelligence(url)
        or {}
    )


    # =====================================================
    # COMPLETE RESULT
    # =====================================================

    return {

        # -------------------------------------------------
        # TARGET
        # -------------------------------------------------

        "url": url,


        # -------------------------------------------------
        # URL STRUCTURE
        # -------------------------------------------------

        "https": {

            "detected": https,

            "status": (
                "✅ HTTPS Detected"
                if https
                else "❌ HTTP Detected"
            )
        },


        "ip_address": {

            "detected": ip_found,

            "status": (
                "⚠️ IP Address Detected"
                if ip_found
                else "✅ Domain Name Used"
            )
        },


        "keywords": {

            "count": keyword_count,

            "matches": keywords
        },


        "url_length": {

            "length": url_length,

            "status": length_status,

            "score": length_score
        },


        "subdomains": {

            "count": subdomain_count,

            "status": subdomain_status,

            "score": subdomain_score
        },


        "at_symbol": {

            "detected": at_found,

            "status": at_status,

            "score": at_score
        },


        "shortener": {

            "detected": shortener_found,

            "status": shortener_status,

            "score": shortener_score
        },


        "hyphens": {

            "count": hyphen_count,

            "status": hyphen_status,

            "score": hyphen_score
        },


        "query_parameters": {

            "count": query_count,

            "matches": suspicious_parameters,

            "status": query_status,

            "score": query_score
        },


        "email_address": {

            "matches": detected_emails,

            "status": email_status,

            "score": email_score
        },


        "file_extension": {

            "extension": file_extension,

            "status": file_status,

            "score": file_score
        },


        "port": {

            "value": port,

            "status": port_status,

            "score": port_score
        },


        # -------------------------------------------------
        # DOMAIN IDENTITY
        # -------------------------------------------------

        "tld": {

            "value": tld,

            "status": tld_status,

            "score": tld_score
        },


        "domain_age": {

            **domain_age,

            "score": domain_age_score
        },


        "entropy": {

            "value": entropy,

            "status": entropy_status,

            "score": entropy_score
        },


        "homograph": {

            "detected": homograph_found,

            "status": homograph_status,

            "score": homograph_score
        },


        "typosquatting": {

            "detected": typosquatting_found,

            "status": typosquatting_status,

            "score": typosquatting_score
        },


        "punycode": {

            "detected": punycode_found,

            "status": punycode_status,

            "score": punycode_score
        },


        "domain_similarity": {

            "matches": similar_words,

            "status": similarity_status,

            "score": similarity_score
        },


        # -------------------------------------------------
        # INFRASTRUCTURE
        # -------------------------------------------------

        "whois": whois_info,

        "dns": dns_records,

        "ssl": ssl_info,


        # -------------------------------------------------
        # PAGE BEHAVIOUR
        # -------------------------------------------------

        "redirects": {

            "count": redirect_count,

            "final_url": final_url,

            "status": redirect_status,

            "score": redirect_score
        },


        "javascript": {

            "patterns": javascript_patterns,

            "status": javascript_status,

            "score": javascript_score
        },


        "forms": {

            "issues": form_issues,

            "status": form_status,

            "score": form_score
        },


        "content": {

            "patterns": content_patterns,

            "status": content_status,

            "score": content_score
        },


        "favicon": {

            "url": favicon_url,

            "status": favicon_status,

            "score": favicon_score
        },


        # -------------------------------------------------
        # SECURITY HEADERS
        # -------------------------------------------------

        "security_headers": {

            "missing": missing_headers,

            "status": headers_status,

            "score": headers_score
        },


        "response_headers": response_headers,


        # -------------------------------------------------
        # WEBSITE DISCOVERY
        # -------------------------------------------------

        "robots": robots,

        "sitemap": sitemap,


        # -------------------------------------------------
        # SERVER INTELLIGENCE
        # -------------------------------------------------

        "technology": technology,

        "file_exposure": file_exposure,

        "http_methods": http_methods,


        # -------------------------------------------------
        # WEB SECURITY
        # -------------------------------------------------

        "cookie_security": cookie_security,

        "cors": cors,

        "mixed_content": mixed_content,


        # -------------------------------------------------
        # EXTERNAL THREAT INTELLIGENCE
        # -------------------------------------------------

        "threat_intelligence": threat_intelligence
    }