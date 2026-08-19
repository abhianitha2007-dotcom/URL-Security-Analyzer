MAX_SCORE = 100


def clamp(value, minimum=0, maximum=MAX_SCORE):
    return max(minimum, min(value, maximum))


def get_score(results, key):
    value = results.get(key, {})

    if not isinstance(value, dict):
        return 0

    try:
        return int(value.get("score", 0) or 0)
    except (TypeError, ValueError):
        return 0


def get_int(data, key, default=0):
    if not isinstance(data, dict):
        return default

    try:
        return int(data.get(key, default) or default)
    except (TypeError, ValueError):
        return default


def add_reason(reasons, condition, message):
    if condition and message not in reasons:
        reasons.append(message)


def calculate_from_results(results):
    reasons = []

    structure_score = 0

    https = results.get("https", {})
    ip_address = results.get("ip_address", {})
    keywords = results.get("keywords", {})

    if not https.get("detected", False):
        structure_score += 20
        add_reason(
            reasons,
            True,
            "The URL does not use HTTPS."
        )

    if ip_address.get("detected", False):
        structure_score += 20
        add_reason(
            reasons,
            True,
            "The URL uses an IP address instead of a domain name."
        )

    keyword_count = get_int(
        keywords,
        "count"
    )

    if keyword_count == 1:
        structure_score += 4
        add_reason(
            reasons,
            True,
            "One suspicious keyword was detected."
        )

    elif keyword_count == 2:
        structure_score += 8
        add_reason(
            reasons,
            True,
            "Multiple suspicious keywords were detected."
        )

    elif 3 <= keyword_count <= 4:
        structure_score += 14
        add_reason(
            reasons,
            True,
            "Several suspicious keywords were detected."
        )

    elif 5 <= keyword_count <= 6:
        structure_score += 18
        add_reason(
            reasons,
            True,
            "Many suspicious keywords were detected."
        )

    elif keyword_count >= 7:
        structure_score += 22
        add_reason(
            reasons,
            True,
            "A very high concentration of suspicious keywords was detected."
        )

    url_length_score = min(
        get_score(results, "url_length"),
        8
    )

    subdomain_score = min(
        get_score(results, "subdomains"),
        8
    )

    hyphen_score = min(
        get_score(results, "hyphens"),
        6
    )

    parameter_score = min(
        get_score(results, "query_parameters"),
        8
    )

    email_score = min(
        get_score(results, "email_address"),
        5
    )

    structure_score += (
        url_length_score
        + subdomain_score
        + hyphen_score
        + parameter_score
        + email_score
    )

    add_reason(
        reasons,
        url_length_score > 0,
        "The URL is longer than normal."
    )

    add_reason(
        reasons,
        subdomain_score >= 6,
        "The URL contains multiple subdomains."
    )

    add_reason(
        reasons,
        parameter_score > 0,
        "Suspicious query parameters were detected."
    )

    add_reason(
        reasons,
        email_score > 0,
        "One or more email addresses were embedded in the URL."
    )

    structure_score = min(
        structure_score,
        35
    )

    strong_score = 0

    at_score = get_score(
        results,
        "at_symbol"
    )

    shortener_score = get_score(
        results,
        "shortener"
    )

    port_score = get_score(
        results,
        "port"
    )

    file_score = get_score(
        results,
        "file_extension"
    )

    file_exposure_score = get_score(
        results,
        "file_exposure"
    )

    strong_score += min(
        at_score,
        20
    )

    strong_score += min(
        shortener_score,
        15
    )

    strong_score += min(
        port_score,
        15
    )

    strong_score += min(
        file_score,
        25
    )

    strong_score += min(
        file_exposure_score,
        20
    )

    add_reason(
        reasons,
        at_score > 0,
        "The URL contains an @ symbol."
    )

    add_reason(
        reasons,
        shortener_score > 0,
        "A URL-shortening service was detected."
    )

    add_reason(
        reasons,
        port_score >= 12,
        "The URL uses a suspicious non-standard port."
    )

    add_reason(
        reasons,
        file_score >= 20,
        "The URL points to a potentially dangerous file."
    )

    add_reason(
        reasons,
        file_exposure_score >= 6,
        "Sensitive server files appear to be publicly exposed."
    )

    strong_score = min(
        strong_score,
        40
    )

    homograph_score = get_score(
        results,
        "homograph"
    )

    punycode_score = get_score(
        results,
        "punycode"
    )

    confirmed_homograph = (
        homograph_score >= 20
    )

    if confirmed_homograph:
        unicode_score = max(
            homograph_score,
            punycode_score
        )
    else:
        unicode_score = min(
            punycode_score,
            5
        )

    entropy_score = get_score(
        results,
        "entropy"
    )

    typo_score = get_score(
        results,
        "typosquatting"
    )

    similarity_score = get_score(
        results,
        "domain_similarity"
    )

    suspicious_name_score = max(
        entropy_score,
        typo_score,
        similarity_score
    )

    strong_domain_naming_pattern = (
        similarity_score >= 20
        and (
            typo_score >= 7
            or confirmed_homograph
        )
    )

    if strong_domain_naming_pattern:
        suspicious_name_score = min(
            similarity_score + 10,
            35
        )

    tld_score = get_score(
        results,
        "tld"
    )

    domain_age_score = get_score(
        results,
        "domain_age"
    )

    domain_score = (
        min(unicode_score, 25)
        + min(suspicious_name_score, 35)
        + min(tld_score, 15)
        + min(domain_age_score, 15)
    )

    domain_score = min(
        domain_score,
        45
    )

    add_reason(
        reasons,
        confirmed_homograph,
        "Possible Unicode homograph attack detected."
    )

    add_reason(
        reasons,
        punycode_score > 0 and not confirmed_homograph,
        "An internationalized Punycode domain was detected."
    )

    add_reason(
        reasons,
        punycode_score > 0 and confirmed_homograph,
        "Punycode was detected in the domain."
    )

    add_reason(
        reasons,
        entropy_score >= 8,
        "The domain name appears randomly generated."
    )

    add_reason(
        reasons,
        typo_score >= 7,
        "The domain contains possible typosquatting patterns."
    )

    add_reason(
        reasons,
        similarity_score >= 6,
        (
            "The domain resembles a known brand or "
            "phishing-related naming pattern."
        )
    )

    add_reason(
        reasons,
        strong_domain_naming_pattern,
        (
            "Multiple domain impersonation indicators "
            "were detected together."
        )
    )

    add_reason(
        reasons,
        tld_score > 0,
        "The domain uses a frequently abused top-level domain."
    )

    add_reason(
        reasons,
        domain_age_score > 0,
        "The domain is newly registered."
    )

    redirect_score = get_score(
        results,
        "redirects"
    )

    header_score = get_score(
        results,
        "security_headers"
    )

    favicon_score = get_score(
        results,
        "favicon"
    )

    robots_score = get_score(
        results,
        "robots"
    )

    sitemap_score = get_score(
        results,
        "sitemap"
    )

    network_score = (
        min(redirect_score, 15)
        + min(header_score, 2)
        + min(favicon_score, 2)
        + min(robots_score, 4)
        + min(sitemap_score, 4)
    )

    network_score = min(
        network_score,
        20
    )

    add_reason(
        reasons,
        redirect_score >= 10,
        "The website performs multiple or suspicious redirects."
    )

    add_reason(
        reasons,
        favicon_score > 0,
        "The favicon is loaded from an external domain."
    )

    add_reason(
        reasons,
        robots_score >= 2,
        "Sensitive paths were disclosed in robots.txt."
    )

    add_reason(
        reasons,
        sitemap_score >= 4,
        "Sensitive URLs were disclosed in the sitemap."
    )

    javascript_score = get_score(
        results,
        "javascript"
    )

    form_score = get_score(
        results,
        "forms"
    )

    content_score = get_score(
        results,
        "content"
    )

    content_behaviour_score = (
        min(javascript_score, 20)
        + min(form_score, 25)
        + min(content_score, 18)
    )

    content_behaviour_score = min(
        content_behaviour_score,
        35
    )

    add_reason(
        reasons,
        javascript_score >= 8,
        "Suspicious JavaScript behaviour was detected."
    )

    add_reason(
        reasons,
        form_score >= 8,
        "Suspicious form behaviour was detected."
    )

    add_reason(
        reasons,
        content_score >= 8,
        "The page contains suspicious phishing language."
    )

    web_security_score = 0

    cors = results.get(
        "cors",
        {}
    )

    mixed_content = results.get(
        "mixed_content",
        {}
    )

    cookie_score = get_score(
        results,
        "cookie_security"
    )

    cors_origin_reflection = bool(
        cors.get(
            "origin_reflection",
            False
        )
    )

    cors_credentials = bool(
        cors.get(
            "allow_credentials",
            False
        )
    )

    cors_allow_origin = str(
        cors.get(
            "allow_origin",
            ""
        )
        or ""
    ).strip()

    if (
        cors_origin_reflection
        and cors_credentials
    ):
        web_security_score += 7

        add_reason(
            reasons,
            True,
            (
                "The website reflects arbitrary cross-origin "
                "requests while allowing credentials."
            )
        )

    elif cors_origin_reflection:
        web_security_score += 3

        add_reason(
            reasons,
            True,
            (
                "The website reflects arbitrary "
                "cross-origin request origins."
            )
        )

    elif (
        cors_allow_origin == "*"
        and cors_credentials
    ):
        web_security_score += 1

    downgraded_to_http = bool(
        mixed_content.get(
            "downgraded_to_http",
            False
        )
    )

    active_mixed_count = get_int(
        mixed_content,
        "active_count"
    )

    passive_mixed_count = get_int(
        mixed_content,
        "passive_count"
    )

    if downgraded_to_http:
        web_security_score += 8

        add_reason(
            reasons,
            True,
            (
                "The HTTPS request was redirected "
                "to an insecure HTTP page."
            )
        )

    elif active_mixed_count > 0:
        web_security_score += min(
            2 + active_mixed_count,
            5
        )

        add_reason(
            reasons,
            True,
            (
                "The HTTPS page loads active "
                "resources over insecure HTTP."
            )
        )

    elif passive_mixed_count >= 3:
        web_security_score += 1

        add_reason(
            reasons,
            True,
            (
                "The HTTPS page loads multiple "
                "resources over insecure HTTP."
            )
        )

    if (
        web_security_score > 0
        and cookie_score > 0
    ):
        web_security_score += 1

    web_security_score = min(
        web_security_score,
        10
    )

    threat_intelligence = results.get(
        "threat_intelligence",
        {}
    )

    threat_checked = bool(
        threat_intelligence.get(
            "checked",
            False
        )
    )

    threat_report_found = bool(
        threat_intelligence.get(
            "report_found",
            False
        )
    )

    threat_submitted = bool(
        threat_intelligence.get(
            "submitted",
            False
        )
    )

    vt_malicious = get_int(
        threat_intelligence,
        "malicious"
    )

    vt_suspicious = get_int(
        threat_intelligence,
        "suspicious"
    )

    vt_total_engines = get_int(
        threat_intelligence,
        "total_engines"
    )

    threat_score = 0

    if (
        threat_checked
        and threat_report_found
    ):
        threat_score = min(
            get_score(
                results,
                "threat_intelligence"
            ),
            45
        )

        if (
            vt_malicious == 1
            and vt_suspicious == 0
        ):
            if vt_total_engines >= 20:
                threat_score = min(
                    threat_score,
                    5
                )
            else:
                threat_score = min(
                    threat_score,
                    8
                )

        elif (
            vt_malicious == 1
            and vt_suspicious > 0
        ):
            threat_score = min(
                threat_score,
                12
            )

        elif (
            vt_malicious == 0
            and vt_suspicious == 1
        ):
            threat_score = min(
                threat_score,
                3
            )

    if (
        threat_report_found
        and vt_malicious > 0
    ):
        if (
            vt_malicious == 1
            and vt_suspicious == 0
        ):
            add_reason(
                reasons,
                True,
                (
                    "VirusTotal reports one isolated malicious "
                    "classification. A single-engine detection "
                    "may be a false positive and is treated as "
                    "weak reputation evidence."
                )
            )

        elif vt_malicious == 1:
            add_reason(
                reasons,
                True,
                (
                    "VirusTotal reports one malicious "
                    "classification together with additional "
                    "suspicious reputation signals."
                )
            )

        else:
            add_reason(
                reasons,
                True,
                (
                    f"VirusTotal reports that {vt_malicious} "
                    "security engines classified this URL "
                    "as malicious."
                )
            )

    if (
        threat_report_found
        and vt_suspicious > 0
    ):
        if vt_suspicious == 1:
            add_reason(
                reasons,
                True,
                (
                    "VirusTotal reports one suspicious "
                    "reputation signal."
                )
            )

        else:
            add_reason(
                reasons,
                True,
                (
                    f"VirusTotal reports {vt_suspicious} "
                    "suspicious reputation signals."
                )
            )

    if (
        threat_submitted
        and not threat_report_found
    ):
        threat_score = 0

    raw_score = (
        structure_score
        + strong_score
        + domain_score
        + network_score
        + content_behaviour_score
        + web_security_score
        + threat_score
    )

    active_categories = sum([
        structure_score >= 12,
        strong_score >= 12,
        domain_score >= 12,
        network_score >= 10,
        content_behaviour_score >= 12,
        web_security_score >= 6,
        threat_score >= 20
    ])

    if active_categories >= 3:
        raw_score += 10

    elif active_categories == 2:
        raw_score += 5

    if strong_domain_naming_pattern:
        raw_score += 12

    risk_score = clamp(
        raw_score
    )

    if threat_report_found:

        if vt_malicious >= 10:
            risk_score = max(
                risk_score,
                80
            )

        elif vt_malicious >= 5:
            risk_score = max(
                risk_score,
                70
            )

        elif vt_malicious >= 3:
            risk_score = max(
                risk_score,
                60
            )

        elif vt_malicious == 2:
            risk_score = max(
                risk_score,
                55
            )

        elif vt_malicious == 1:

            if vt_suspicious >= 5:
                risk_score = max(
                    risk_score,
                    45
                )

            elif vt_suspicious >= 2:
                risk_score = max(
                    risk_score,
                    35
                )

        elif vt_suspicious >= 5:
            risk_score = max(
                risk_score,
                45
            )

        elif vt_suspicious >= 2:
            risk_score = max(
                risk_score,
                35
            )

        elif vt_suspicious == 1:
            pass

    if downgraded_to_http:
        risk_score = max(
            risk_score,
            20
        )

    risk_score = clamp(
        risk_score
    )

    if risk_score <= 15:
        verdict = "Safe"

    elif risk_score <= 30:
        verdict = "Low Risk"

    elif risk_score <= 50:
        verdict = "Medium Risk"

    elif risk_score <= 75:
        verdict = "High Risk"

    else:
        verdict = "Critical"

    if not reasons:
        reasons.append(
            "No major suspicious indicators were detected."
        )

    return (
        risk_score,
        verdict,
        reasons
    )


def calculate_risk(results):
    if not isinstance(results, dict):
        raise TypeError(
            (
                "calculate_risk expects the "
                "Detection Manager results dictionary."
            )
        )

    return calculate_from_results(
        results
    )