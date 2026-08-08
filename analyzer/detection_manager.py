import re

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import unquote, urlparse

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
from analyzer.threat_intelligence_checker import check_threat_intelligence
from analyzer.url_validator import get_network_target_status


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


def unavailable_domain_age():
    return {
        "age": "Unavailable",
        "risk": False,
        "confirmed_new": False,
        "message": "Registration data unavailable.",
        "score": 0
    }


def unavailable_whois():
    return {
        "registrar": "Unavailable",
        "creation_date": "Unavailable",
        "expiration_date": "Unavailable",
        "updated_date": "Unavailable",
        "organization": "Unavailable",
        "country": "Unavailable",
        "status": "Unavailable",
        "name_servers": "Unavailable"
    }


def unavailable_dns():
    return {
        "status": "Unavailable",
        "message": "DNS information could not be verified.",
        "records": {}
    }


def unavailable_ssl():
    return {
        "status": "Unavailable",
        "issuer": "Unavailable",
        "subject": "Unavailable",
        "valid_from": "Unavailable",
        "valid_to": "Unavailable",
        "days_remaining": None
    }


def unavailable_response_headers():
    return {
        "status": "Unavailable",
        "headers": {},
        "score": 0
    }


def unavailable_robots():
    return {
        "found": False,
        "url": None,
        "status_code": None,
        "status": "Could not verify robots.txt",
        "score": 0,
        "disallow_count": 0,
        "suspicious_paths": [],
        "sitemap_urls": []
    }


def unavailable_sitemap():
    return {
        "found": False,
        "status": "Unavailable",
        "score": 0,
        "sitemap_files": [],
        "url_count": 0,
        "suspicious_urls": [],
        "attention_urls": [],
        "errors": []
    }


def unavailable_technology():
    return {
        "status": "Unavailable",
        "technologies": [],
        "score": 0
    }


def unavailable_file_exposure():
    return {
        "status": "Unavailable",
        "score": 0,
        "exposed_files": [],
        "checked": False
    }


def unavailable_http_methods():
    return {
        "status": "Unavailable",
        "score": 0,
        "allowed_methods": []
    }


def unavailable_cookie_security():
    return {
        "status": "Unavailable",
        "score": 0,
        "issues": []
    }


def unavailable_cors():
    return {
        "status": "Unavailable",
        "score": 0,
        "origin_reflection": False,
        "allow_credentials": False,
        "allow_origin": ""
    }


def unavailable_mixed_content():
    return {
        "status": "Unavailable",
        "score": 0,
        "downgraded_to_http": False,
        "active_count": 0,
        "passive_count": 0,
        "active_resources": [],
        "passive_resources": []
    }


def unavailable_threat_intelligence():
    return {
        "checked": False,
        "report_found": False,
        "submitted": False,
        "analysis_id": None,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "timeout": 0,
        "total_engines": 0,
        "reputation": 0,
        "categories": [],
        "last_analysis_date": "Unavailable",
        "score": 0,
        "issues": [],
        "status": "Unavailable",
        "source": "VirusTotal"
    }


def build_content_warning(
    url,
    threat_intelligence
):
    categories = threat_intelligence.get(
        "categories",
        []
    )

    if not isinstance(categories, list):
        categories = []

    category_text = " ".join(
        str(category).lower()
        for category in categories
    )

    try:
        parsed = urlparse(url)

        url_text = unquote(
            " ".join(
                [
                    parsed.hostname or "",
                    parsed.path or "",
                    parsed.query or ""
                ]
            )
        ).lower()

    except Exception:
        url_text = str(url).lower()

    url_tokens = set(
        re.findall(
            r"[a-z0-9]+",
            url_text
        )
    )

    adult_category_terms = (
        "adult",
        "porn",
        "pornography",
        "sexually explicit",
        "explicit content",
        "nudity",
        "mature content"
    )

    adult_url_terms = {
        "porn",
        "pornography",
        "xxx",
        "hentai",
        "nsfw"
    }

    gambling_category_terms = (
        "gambling",
        "betting",
        "casino",
        "lottery",
        "sports betting",
        "sportsbook",
        "bookmaking"
    )

    gambling_url_terms = {
        "bet",
        "bets",
        "betting",
        "gambling",
        "casino",
        "casinos",
        "sportsbook",
        "sportsbooks",
        "bookmaker",
        "bookmakers",
        "poker",
        "slots",
        "lottery"
    }

    financial_category_terms = (
        "cryptocurrency",
        "crypto",
        "financial",
        "financial services",
        "financial data and services",
        "finance",
        "investment",
        "banking",
        "digital currency",
        "digital wallet"
    )

    financial_url_terms = {
        "crypto",
        "cryptocurrency",
        "banking",
        "finance",
        "financial",
        "investment",
        "investments",
        "investing",
        "trading",
        "wallet",
        "wallets"
    }

    adult_category_match = any(
        term in category_text
        for term in adult_category_terms
    )

    adult_url_match = bool(
        adult_url_terms.intersection(
            url_tokens
        )
    )

    gambling_category_match = any(
        term in category_text
        for term in gambling_category_terms
    )

    gambling_url_match = bool(
        gambling_url_terms.intersection(
            url_tokens
        )
    )

    financial_category_match = any(
        term in category_text
        for term in financial_category_terms
    )

    financial_url_match = bool(
        financial_url_terms.intersection(
            url_tokens
        )
    )

    if (
        adult_category_match
        or adult_url_match
    ):
        return {
            "show": True,
            "type": "adult",
            "icon": "🔞",
            "title": "Content Warning",
            "message": (
                "This website may contain adult "
                "or explicit material."
            )
        }

    if (
        gambling_category_match
        or gambling_url_match
    ):
        return {
            "show": True,
            "type": "gambling",
            "icon": "⚠️",
            "title": "Gambling Warning",
            "message": (
                "This website may contain gambling "
                "or betting services."
            )
        }

    if (
        financial_category_match
        or financial_url_match
    ):
        return {
            "show": True,
            "type": "financial",
            "icon": "⚠️",
            "title": "Financial Caution",
            "message": (
                "This website may involve financial "
                "transactions, investments, cryptocurrency "
                "or digital wallets. Verify the site carefully "
                "before entering sensitive information."
            )
        }

    return {
        "show": False,
        "type": None,
        "icon": None,
        "title": None,
        "message": None
    }


def build_scan_status(network_status):
    available = bool(
        network_status.get(
            "available",
            False
        )
    )

    safe = bool(
        network_status.get(
            "safe",
            False
        )
    )

    if available and safe:
        return {
            "mode": "full",
            "label": "Full Analysis",
            "complete": True,
            "network_available": True,
            "code": network_status.get(
                "code",
                "public_target"
            ),
            "message": (
                "URL, domain, network, webpage and "
                "threat-intelligence checks were performed."
            )
        }

    code = network_status.get(
        "code",
        "network_unavailable"
    )

    if code == "private_target":
        message = (
            "The destination could not be accessed because "
            "it resolved to a non-public network address. "
            "Only safe offline and external reputation "
            "checks were performed."
        )

    else:
        message = (
            "The website could not be reached or resolved "
            "from the analysis server. URL-based and available "
            "external intelligence checks were still performed."
        )

    return {
        "mode": "partial",
        "label": "Partial Analysis",
        "complete": False,
        "network_available": False,
        "code": code,
        "message": message
    }


def run_full_network_checks(url):
    with ThreadPoolExecutor(
        max_workers=MAX_NETWORK_WORKERS
    ) as executor:

        futures = {
            "domain_age": executor.submit(
                check_domain_age,
                url
            ),
            "whois": executor.submit(
                get_whois_info,
                url
            ),
            "dns": executor.submit(
                get_dns_records,
                url
            ),
            "ssl": executor.submit(
                get_ssl_info,
                url
            ),
            "redirects": executor.submit(
                check_redirects,
                url
            ),
            "javascript": executor.submit(
                check_javascript,
                url
            ),
            "forms": executor.submit(
                check_forms,
                url
            ),
            "content": executor.submit(
                check_content,
                url
            ),
            "favicon": executor.submit(
                check_favicon,
                url
            ),
            "security_headers": executor.submit(
                check_security_headers,
                url
            ),
            "response_headers": executor.submit(
                check_response_headers,
                url
            ),
            "robots": executor.submit(
                check_robots,
                url
            ),
            "technology": executor.submit(
                check_technology,
                url
            ),
            "file_exposure": executor.submit(
                check_file_exposure,
                url
            ),
            "http_methods": executor.submit(
                check_http_methods,
                url
            ),
            "cookie_security": executor.submit(
                check_cookie_security,
                url
            ),
            "cors": executor.submit(
                check_cors_security,
                url
            ),
            "mixed_content": executor.submit(
                check_mixed_content,
                url
            ),
            "threat_intelligence": executor.submit(
                check_threat_intelligence,
                url
            )
        }

        robots = future_value(
            futures["robots"],
            unavailable_robots()
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
            unavailable_domain_age()
        )

        whois_info = future_value(
            futures["whois"],
            unavailable_whois()
        )

        dns_records = future_value(
            futures["dns"],
            unavailable_dns()
        )

        ssl_info = future_value(
            futures["ssl"],
            unavailable_ssl()
        )

        redirects = future_value(
            futures["redirects"],
            (
                0,
                url,
                "Unavailable",
                0
            )
        )

        javascript = future_value(
            futures["javascript"],
            (
                [],
                "Unavailable",
                0
            )
        )

        forms = future_value(
            futures["forms"],
            (
                [],
                "Unavailable",
                0
            )
        )

        content = future_value(
            futures["content"],
            (
                [],
                "Unavailable",
                0
            )
        )

        favicon = future_value(
            futures["favicon"],
            (
                None,
                "Unavailable",
                0
            )
        )

        security_headers = future_value(
            futures["security_headers"],
            (
                [],
                "Unavailable",
                0
            )
        )

        response_headers = future_value(
            futures["response_headers"],
            unavailable_response_headers()
        )

        technology = future_value(
            futures["technology"],
            unavailable_technology()
        )

        file_exposure = future_value(
            futures["file_exposure"],
            unavailable_file_exposure()
        )

        http_methods = future_value(
            futures["http_methods"],
            unavailable_http_methods()
        )

        cookie_security = future_value(
            futures["cookie_security"],
            unavailable_cookie_security()
        )

        cors = future_value(
            futures["cors"],
            unavailable_cors()
        )

        mixed_content = future_value(
            futures["mixed_content"],
            unavailable_mixed_content()
        )

        threat_intelligence = future_value(
            futures["threat_intelligence"],
            unavailable_threat_intelligence()
        )

        sitemap = future_value(
            sitemap_future,
            unavailable_sitemap()
        )

    return {
        "domain_age": domain_age,
        "whois": whois_info,
        "dns": dns_records,
        "ssl": ssl_info,
        "redirects": redirects,
        "javascript": javascript,
        "forms": forms,
        "content": content,
        "favicon": favicon,
        "security_headers": security_headers,
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


def run_partial_network_checks(url):
    with ThreadPoolExecutor(
        max_workers=3
    ) as executor:

        futures = {
            "domain_age": executor.submit(
                check_domain_age,
                url
            ),
            "whois": executor.submit(
                get_whois_info,
                url
            ),
            "threat_intelligence": executor.submit(
                check_threat_intelligence,
                url
            )
        }

        domain_age = future_value(
            futures["domain_age"],
            unavailable_domain_age()
        )

        whois_info = future_value(
            futures["whois"],
            unavailable_whois()
        )

        threat_intelligence = future_value(
            futures["threat_intelligence"],
            unavailable_threat_intelligence()
        )

    return {
        "domain_age": domain_age,
        "whois": whois_info,
        "dns": unavailable_dns(),
        "ssl": unavailable_ssl(),
        "redirects": (
            0,
            url,
            "Unavailable",
            0
        ),
        "javascript": (
            [],
            "Unavailable",
            0
        ),
        "forms": (
            [],
            "Unavailable",
            0
        ),
        "content": (
            [],
            "Unavailable",
            0
        ),
        "favicon": (
            None,
            "Unavailable",
            0
        ),
        "security_headers": (
            [],
            "Unavailable",
            0
        ),
        "response_headers": unavailable_response_headers(),
        "robots": unavailable_robots(),
        "sitemap": unavailable_sitemap(),
        "technology": unavailable_technology(),
        "file_exposure": unavailable_file_exposure(),
        "http_methods": unavailable_http_methods(),
        "cookie_security": unavailable_cookie_security(),
        "cors": unavailable_cors(),
        "mixed_content": unavailable_mixed_content(),
        "threat_intelligence": threat_intelligence
    }


def run_all_checks(url):
    https = check_https(url)

    ip_found = contains_ip(url)

    keyword_count, keywords = check_keywords(
        url
    )

    (
        url_length,
        length_status,
        length_score
    ) = check_url_length(
        url
    )

    (
        subdomain_count,
        subdomain_status,
        subdomain_score
    ) = count_subdomains(
        url
    )

    (
        at_found,
        at_status,
        at_score
    ) = check_at_symbol(
        url
    )

    (
        shortener_found,
        shortener_status,
        shortener_score
    ) = check_shortener(
        url
    )

    (
        hyphen_count,
        hyphen_status,
        hyphen_score
    ) = check_hyphen(
        url
    )

    (
        port,
        port_status,
        port_score
    ) = check_port(
        url
    )

    (
        query_count,
        suspicious_parameters,
        query_status,
        query_score
    ) = check_query_parameters(
        url
    )

    (
        file_extension,
        file_status,
        file_score
    ) = check_file_extension(
        url
    )

    (
        detected_emails,
        email_status,
        email_score
    ) = check_email_address(
        url
    )

    (
        tld,
        tld_status,
        tld_score
    ) = check_tld(
        url
    )

    (
        entropy,
        entropy_status,
        entropy_score
    ) = check_entropy(
        url
    )

    (
        homograph_found,
        homograph_status,
        homograph_score
    ) = check_homograph(
        url
    )

    (
        typosquatting_found,
        typosquatting_status,
        typosquatting_score
    ) = check_typosquatting(
        url
    )

    (
        punycode_found,
        punycode_status,
        punycode_score
    ) = check_punycode(
        url
    )

    (
        similar_words,
        similarity_status,
        similarity_score
    ) = check_domain_similarity(
        url
    )

    network_status = get_network_target_status(
        url
    )

    scan_status = build_scan_status(
        network_status
    )

    if scan_status["complete"]:
        network_results = run_full_network_checks(
            url
        )

    else:
        network_results = run_partial_network_checks(
            url
        )

    domain_age = network_results[
        "domain_age"
    ]

    whois_info = network_results[
        "whois"
    ]

    dns_records = network_results[
        "dns"
    ]

    ssl_info = network_results[
        "ssl"
    ]

    (
        redirect_count,
        final_url,
        redirect_status,
        redirect_score
    ) = network_results[
        "redirects"
    ]

    (
        javascript_patterns,
        javascript_status,
        javascript_score
    ) = network_results[
        "javascript"
    ]

    (
        form_issues,
        form_status,
        form_score
    ) = network_results[
        "forms"
    ]

    (
        content_patterns,
        content_status,
        content_score
    ) = network_results[
        "content"
    ]

    (
        favicon_url,
        favicon_status,
        favicon_score
    ) = network_results[
        "favicon"
    ]

    (
        missing_headers,
        headers_status,
        headers_score
    ) = network_results[
        "security_headers"
    ]

    response_headers = network_results[
        "response_headers"
    ]

    robots = network_results[
        "robots"
    ]

    sitemap = network_results[
        "sitemap"
    ]

    technology = network_results[
        "technology"
    ]

    file_exposure = network_results[
        "file_exposure"
    ]

    http_methods = network_results[
        "http_methods"
    ]

    cookie_security = network_results[
        "cookie_security"
    ]

    cors = network_results[
        "cors"
    ]

    mixed_content = network_results[
        "mixed_content"
    ]

    threat_intelligence = network_results[
        "threat_intelligence"
    ]

    content_warning = build_content_warning(
        url,
        threat_intelligence
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

        "scan_status": scan_status,

        "network_status": network_status,

        "content_warning": content_warning,

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