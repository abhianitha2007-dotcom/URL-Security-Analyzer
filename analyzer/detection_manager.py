from concurrent.futures import ThreadPoolExecutor

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


MAX_NETWORK_WORKERS = 8


def safe_int(value, default=0):
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def future_value(future, default):
    try:
        value = future.result()

        if value is None:
            return default

        return value

    except Exception:
        return default


def run_all_checks(url):

    # Fast local checks
    https = check_https(url)
    ip_found = contains_ip(url)

    keyword_count, keywords = check_keywords(url)

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

    # Network-heavy checks
    with ThreadPoolExecutor(
        max_workers=MAX_NETWORK_WORKERS
    ) as executor:

        futures = {
            "domain_age":
                executor.submit(
                    check_domain_age,
                    url
                ),

            "whois":
                executor.submit(
                    get_whois_info,
                    url
                ),

            "dns":
                executor.submit(
                    get_dns_records,
                    url
                ),

            "ssl":
                executor.submit(
                    get_ssl_info,
                    url
                ),

            "redirects":
                executor.submit(
                    check_redirects,
                    url
                ),

            "javascript":
                executor.submit(
                    check_javascript,
                    url
                ),

            "forms":
                executor.submit(
                    check_forms,
                    url
                ),

            "content":
                executor.submit(
                    check_content,
                    url
                ),

            "favicon":
                executor.submit(
                    check_favicon,
                    url
                ),

            "security_headers":
                executor.submit(
                    check_security_headers,
                    url
                ),

            "response_headers":
                executor.submit(
                    check_response_headers,
                    url
                ),

            "robots":
                executor.submit(
                    check_robots,
                    url
                ),

            "technology":
                executor.submit(
                    check_technology,
                    url
                ),

            "file_exposure":
                executor.submit(
                    check_file_exposure,
                    url
                ),

            "http_methods":
                executor.submit(
                    check_http_methods,
                    url
                ),

            "cookie_security":
                executor.submit(
                    check_cookie_security,
                    url
                ),

            "cors":
                executor.submit(
                    check_cors_security,
                    url
                ),

            "mixed_content":
                executor.submit(
                    check_mixed_content,
                    url
                ),

            "threat_intelligence":
                executor.submit(
                    check_threat_intelligence,
                    url
                )
        }

        robots = future_value(
            futures["robots"],
            {}
        )

        sitemap_future = executor.submit(
            check_sitemap,
            url,
            discovered_sitemaps=robots.get(
                "sitemap_urls",
                []
            )
        )

        domain_age = future_value(
            futures["domain_age"],
            {}
        )

        whois_info = future_value(
            futures["whois"],
            {}
        )

        dns_records = future_value(
            futures["dns"],
            {}
        )

        ssl_info = future_value(
            futures["ssl"],
            {}
        )

        (
            redirect_count,
            final_url,
            redirect_status,
            redirect_score
        ) = future_value(
            futures["redirects"],
            (
                0,
                url,
                "Not Checked",
                0
            )
        )

        (
            javascript_patterns,
            javascript_status,
            javascript_score
        ) = future_value(
            futures["javascript"],
            (
                [],
                "Not Checked",
                0
            )
        )

        (
            form_issues,
            form_status,
            form_score
        ) = future_value(
            futures["forms"],
            (
                [],
                "Not Checked",
                0
            )
        )

        (
            content_patterns,
            content_status,
            content_score
        ) = future_value(
            futures["content"],
            (
                [],
                "Not Checked",
                0
            )
        )

        (
            favicon_url,
            favicon_status,
            favicon_score
        ) = future_value(
            futures["favicon"],
            (
                None,
                "Not Checked",
                0
            )
        )

        (
            missing_headers,
            headers_status,
            headers_score
        ) = future_value(
            futures["security_headers"],
            (
                [],
                "Not Checked",
                0
            )
        )

        response_headers = future_value(
            futures["response_headers"],
            {}
        )

        technology = future_value(
            futures["technology"],
            {}
        )

        file_exposure = future_value(
            futures["file_exposure"],
            {}
        )

        http_methods = future_value(
            futures["http_methods"],
            {}
        )

        cookie_security = future_value(
            futures["cookie_security"],
            {}
        )

        cors = future_value(
            futures["cors"],
            {}
        )

        mixed_content = future_value(
            futures["mixed_content"],
            {}
        )

        threat_intelligence = future_value(
            futures["threat_intelligence"],
            {}
        )

        sitemap = future_value(
            sitemap_future,
            {}
        )

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

    return {
        "url": url,

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

        "whois": whois_info,
        "dns": dns_records,
        "ssl": ssl_info,

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

        "security_headers": {
            "missing": missing_headers,
            "status": headers_status,
            "score": headers_score
        },

        "response_headers": response_headers,

        "robots": robots,
        "sitemap": sitemap,

        "technology": technology,
        "file_exposure": file_exposure,
        "http_methods": http_methods,

        "cookie_security": cookie_security,
        "cors": cors,
        "mixed_content": mixed_content,

        "threat_intelligence": threat_intelligence
    }