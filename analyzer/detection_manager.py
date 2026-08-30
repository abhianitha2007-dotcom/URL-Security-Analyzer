"""Coordinate deterministic URL analysis and return one complete result."""

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from analyzer.at_symbol_checker import check_at_symbol
from analyzer.content_checker import check_content
from analyzer.content_warning import classify_content
from analyzer.cookie_security_checker import check_cookie_security
from analyzer.cors_checker import check_cors_security
from analyzer.dns_checker import get_dns_records
from analyzer.domain_age_checker import check_domain_age
from analyzer.email_checker import check_email_address
from analyzer.entropy_checker import check_entropy
from analyzer.exceptions import AnalysisIncompleteError
from analyzer.favicon_checker import check_favicon
from analyzer.file_exposure_checker import check_file_exposure
from analyzer.file_extension_checker import check_file_extension
from analyzer.form_checker import check_forms
from analyzer.homograph_checker import check_homograph
from analyzer.http_methods_checker import check_http_methods
from analyzer.https_checker import check_https
from analyzer.hyphen_checker import check_hyphen
from analyzer.ip_checker import contains_ip
from analyzer.javascript_checker import check_javascript
from analyzer.keyword_checker import check_url_language
from analyzer.length_checker import check_url_length
from analyzer.mixed_content_checker import check_mixed_content
from analyzer.page_snapshot import capture_page, snapshot_metadata
from analyzer.port_checker import check_port
from analyzer.punycode_checker import check_punycode
from analyzer.query_checker import check_query_parameters
from analyzer.redirect_checker import check_redirects
from analyzer.response_header_checker import check_response_headers
from analyzer.robots_checker import check_robots
from analyzer.security_headers_checker import check_security_headers
from analyzer.shortener_checker import check_shortener
from analyzer.sitemap_checker import check_sitemap
from analyzer.ssl_checker import get_ssl_info
from analyzer.subdomain_checker import count_subdomains
from analyzer.technology_checker import check_technology
from analyzer.threat_intelligence_checker import check_threat_intelligence
from analyzer.tld_checker import check_tld
from analyzer.typosquatting_checker import check_typosquatting
from analyzer.url_validator import get_network_target_status
from analyzer.whois_checker import get_whois_info


MAX_NETWORK_WORKERS = 8
FAILURE_MARKERS = (
    "not checked",
    "unavailable",
    "could not verify",
    "request failed",
    "request timed out",
    "parsing failed",
    "invalid url",
)
TUPLE_RESULT_FIELDS = {
    "redirects": ("count", "final_url", "status", "score"),
    "shortener": ("detected", "status", "score"),
    "javascript": ("patterns", "status", "score"),
    "forms": ("issues", "status", "score"),
    "content": ("matches", "status", "score"),
    "favicon": ("url", "status", "score"),
    "security_headers": ("missing", "status", "score"),
}


def _int(value, default=0):
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _required(future, name):
    try:
        value = future.result()
    except AnalysisIncompleteError:
        raise
    except Exception as error:
        raise AnalysisIncompleteError(
            f"The {name.replace('_', ' ')} check failed. No risk score was produced.",
            (name,),
        ) from error
    if value is None:
        raise AnalysisIncompleteError(
            f"The {name.replace('_', ' ')} check returned no result. No risk score was produced.",
            (name,),
        )
    return value


def _status(name, value):
    if isinstance(value, dict):
        return str(value.get("status", ""))
    return ""


def _normalize_network_result(name, value):
    """Convert legacy checker tuples into the shared result schema."""
    fields = TUPLE_RESULT_FIELDS.get(name)
    if fields is None or isinstance(value, dict):
        return value
    if not isinstance(value, (tuple, list)) or len(value) != len(fields):
        raise AnalysisIncompleteError(
            f"The {name.replace('_', ' ')} check returned an invalid result. "
            "No risk score was produced.",
            (name,),
        )
    return dict(zip(fields, value))


def _validate_complete_network_results(url, results):
    """Reject operational gaps instead of converting them into neutral scores."""
    failed = []
    checked_statuses = (
        "redirects",
        "shortener",
        "javascript",
        "forms",
        "content",
        "favicon",
        "security_headers",
        "response_headers",
        "technology",
        "http_methods",
        "cookie_security",
        "cors",
        "mixed_content",
    )
    for name in checked_statuses:
        status = _status(name, results.get(name)).lower()
        if not status or any(marker in status for marker in FAILURE_MARKERS):
            failed.append(name)

    if urlsplit(url).scheme.lower() == "https":
        ssl_status = _status("ssl", results.get("ssl")).lower()
        if "could not retrieve" in ssl_status or "unavailable" in ssl_status:
            failed.append("ssl")

    age_message = str(results["domain_age"].get("message", "")).lower()
    if "lookup failed" in age_message or "invalid domain" in age_message:
        failed.append("domain_age")

    robots = results["robots"]
    robots_status = str(robots.get("status", "")).lower()
    if any(marker in robots_status for marker in ("could not verify", "rate limited", "temporarily unavailable")):
        failed.append("robots")

    sitemap = results["sitemap"]
    if sitemap.get("errors"):
        failed.append("sitemap")

    exposure = results["file_exposure"]
    if _int(exposure.get("checked_count")) < len(exposure.get("results", [])):
        failed.append("file_exposure")

    intelligence = results["threat_intelligence"]
    if not intelligence.get("checked", False):
        failed.append("threat_intelligence")

    failed = sorted(set(failed))
    if failed:
        labels = ", ".join(item.replace("_", " ") for item in failed)
        raise AnalysisIncompleteError(
            f"Complete analysis is unavailable because these checks did not finish: {labels}. "
            "No risk score or report was produced.",
            failed,
        )


def _not_applicable_ssl():
    return {
        "issuer": "Not applicable",
        "valid_from": "Not applicable",
        "valid_to": "Not applicable",
        "days_remaining": None,
        "protocol": "Not applicable",
        "cipher": "Not applicable",
        "status": "Not applicable — URL uses HTTP",
    }


def run_full_network_checks(url):
    """Run network modules against one immutable base-page response."""
    page = capture_page(url)
    is_https = urlsplit(url).scheme.lower() == "https"

    with ThreadPoolExecutor(max_workers=MAX_NETWORK_WORKERS) as executor:
        futures = {
            "domain_age": executor.submit(check_domain_age, url),
            "whois": executor.submit(get_whois_info, url),
            "dns": executor.submit(get_dns_records, url),
            "redirects": executor.submit(check_redirects, url, page),
            "shortener": executor.submit(check_shortener, url, page),
            "javascript": executor.submit(check_javascript, url, page),
            "forms": executor.submit(check_forms, url, page),
            "content": executor.submit(check_content, url, page),
            "favicon": executor.submit(check_favicon, url, page),
            "security_headers": executor.submit(check_security_headers, url, page),
            "response_headers": executor.submit(check_response_headers, url, page),
            "robots": executor.submit(check_robots, url),
            "technology": executor.submit(check_technology, url, page),
            "file_exposure": executor.submit(check_file_exposure, url),
            "http_methods": executor.submit(check_http_methods, url),
            "cookie_security": executor.submit(check_cookie_security, url, page),
            "cors": executor.submit(check_cors_security, url),
            "mixed_content": executor.submit(check_mixed_content, url, page),
            "threat_intelligence": executor.submit(check_threat_intelligence, url),
        }
        if is_https:
            futures["ssl"] = executor.submit(get_ssl_info, url)

        robots = _required(futures["robots"], "robots")
        sitemap_future = executor.submit(
            check_sitemap,
            url,
            discovered_sitemaps=robots.get("sitemap_urls", []),
        )

        results = {
            name: _normalize_network_result(name, _required(future, name))
            for name, future in futures.items()
            if name != "robots"
        }
        results["robots"] = robots
        results["sitemap"] = _required(sitemap_future, "sitemap")

    if not is_https:
        results["ssl"] = _not_applicable_ssl()
    results["snapshot"] = snapshot_metadata(page)
    results["content_warning"] = classify_content(
        url,
        threat_intelligence=results["threat_intelligence"],
        response=page,
    )
    _validate_complete_network_results(url, results)
    return results


def _network_status_or_error(url):
    status = get_network_target_status(url)
    if status.get("available") and status.get("safe"):
        return status

    code = status.get("code", "network_unavailable")
    if code == "private_target":
        message = (
            "The destination resolved to a private or local network address "
            "and cannot be analyzed safely."
        )
    else:
        message = (
            "The domain could not be resolved or reached from the analysis server. "
            "No risk score was produced. Please retry."
        )
    raise AnalysisIncompleteError(message, ("network_target",))


def _offline_checks(url):
    language = check_url_language(url)
    url_length, length_status, length_score = check_url_length(url)
    subdomains, subdomain_status, subdomain_score = count_subdomains(url)
    at_found, at_status, at_score = check_at_symbol(url)
    hyphens, hyphen_status, hyphen_score = check_hyphen(url)
    port, port_status, port_score = check_port(url)
    query_count, query_names, query_status, query_score = check_query_parameters(url)
    extension, extension_status, extension_score = check_file_extension(url)
    emails, email_status, email_score = check_email_address(url)
    tld, tld_status, tld_score = check_tld(url)
    entropy, entropy_status, entropy_score = check_entropy(url)
    homograph, homograph_status, homograph_score = check_homograph(url)
    typo, typo_status, typo_score = check_typosquatting(url)
    punycode, punycode_status, punycode_score = check_punycode(url)
    https = check_https(url)
    ip_found = contains_ip(url)

    return {
        "https": {
            "detected": https,
            "status": "HTTPS detected" if https else "HTTP detected",
        },
        "ip_address": {
            "detected": ip_found,
            "status": "IP address used" if ip_found else "Domain name used",
        },
        "keywords": language,
        "url_length": {"length": url_length, "status": length_status, "score": length_score},
        "subdomains": {"count": subdomains, "status": subdomain_status, "score": subdomain_score},
        "at_symbol": {"detected": at_found, "status": at_status, "score": at_score},
        "hyphens": {"count": hyphens, "status": hyphen_status, "score": hyphen_score},
        "query_parameters": {
            "count": query_count,
            "matches": query_names,
            "status": query_status,
            "score": query_score,
        },
        "email_address": {"matches": emails, "status": email_status, "score": email_score},
        "file_extension": {"extension": extension, "status": extension_status, "score": extension_score},
        "port": {"value": port, "status": port_status, "score": port_score},
        "tld": {"value": tld, "status": tld_status, "score": tld_score},
        "entropy": {"value": entropy, "status": entropy_status, "score": entropy_score},
        "homograph": {"detected": homograph, "status": homograph_status, "score": homograph_score},
        "typosquatting": {"detected": typo, "status": typo_status, "score": typo_score},
        "punycode": {"detected": punycode, "status": punycode_status, "score": punycode_score},
        "domain_similarity": {
            "matches": language["evidence_tokens"],
            "status": language["status"],
            "score": 0,
        },
    }


def run_all_checks(url):
    """Return a complete, score-ready analysis or raise without a score."""
    network_status = _network_status_or_error(url)
    try:
        results = {"url": url, **_offline_checks(url)}
        network = run_full_network_checks(url)
    except AnalysisIncompleteError:
        raise
    except Exception as error:
        raise AnalysisIncompleteError(
            "A required analysis module failed. No risk score or report was produced.",
            ("analysis_engine",),
        ) from error

    domain_age = network["domain_age"]
    domain_age_score = 20 if domain_age.get("confirmed_new", False) else 0
    results.update(network)
    results["domain_age"] = {**domain_age, "score": domain_age_score}
    results["network_status"] = network_status
    results["scan_status"] = {
        "mode": "complete",
        "label": "Complete Analysis",
        "complete": True,
        "network_available": True,
        "code": network_status.get("code", "public_target"),
        "failed_checks": [],
        "message": (
            "All required URL, domain, network, webpage, and reputation checks completed."
        ),
    }
    return results
