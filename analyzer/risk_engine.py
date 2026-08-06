MAX_SCORE = 100


def clamp(value, minimum=0, maximum=MAX_SCORE):
    return max(
        minimum,
        min(value, maximum)
    )


def get_score(results, key):
    value = results.get(
        key,
        {}
    )

    if isinstance(value, dict):
        return int(
            value.get(
                "score",
                0
            )
            or 0
        )

    return 0


def add_reason(
    reasons,
    condition,
    message
):
    if condition and message not in reasons:
        reasons.append(message)


def calculate_from_results(results):
    """
    Calculates the final URL risk score using
    all Detection Manager results.

    Returns:
        risk_score,
        verdict,
        reasons
    """

    reasons = []

    # ======================================================
    # URL STRUCTURE
    # Maximum contribution: 35
    # ======================================================

    structure_score = 0

    https = results.get(
        "https",
        {}
    )

    ip_address = results.get(
        "ip_address",
        {}
    )

    keywords = results.get(
        "keywords",
        {}
    )

    if not https.get(
        "detected",
        False
    ):
        structure_score += 20

        add_reason(
            reasons,
            True,
            "The URL does not use HTTPS."
        )

    if ip_address.get(
        "detected",
        False
    ):
        structure_score += 20

        add_reason(
            reasons,
            True,
            (
                "The URL uses an IP address "
                "instead of a domain name."
            )
        )

    keyword_count = int(
        keywords.get(
            "count",
            0
        )
        or 0
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
            (
                "Multiple suspicious keywords "
                "were detected."
            )
        )

    elif keyword_count >= 3:
        structure_score += 14

        add_reason(
            reasons,
            True,
            "Many suspicious keywords were detected."
        )

    url_length_score = min(
        get_score(
            results,
            "url_length"
        ),
        8
    )

    subdomain_score = min(
        get_score(
            results,
            "subdomains"
        ),
        8
    )

    hyphen_score = min(
        get_score(
            results,
            "hyphens"
        ),
        6
    )

    parameter_score = min(
        get_score(
            results,
            "query_parameters"
        ),
        8
    )

    email_score = min(
        get_score(
            results,
            "email_address"
        ),
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
        (
            "Suspicious query parameters "
            "were detected."
        )
    )

    add_reason(
        reasons,
        email_score > 0,
        (
            "One or more email addresses "
            "were embedded in the URL."
        )
    )

    structure_score = min(
        structure_score,
        35
    )

    # ======================================================
    # STRONG URL INDICATORS
    # Maximum contribution: 40
    # ======================================================

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
        (
            "The URL uses a suspicious "
            "non-standard port."
        )
    )

    add_reason(
        reasons,
        file_score >= 20,
        (
            "The URL points to a potentially "
            "dangerous file."
        )
    )

    strong_score = min(
        strong_score,
        40
    )

    # ======================================================
    # DOMAIN IDENTITY
    # Maximum contribution: 45
    # ======================================================

    homograph_score = get_score(
        results,
        "homograph"
    )

    punycode_score = get_score(
        results,
        "punycode"
    )

    unicode_score = max(
        homograph_score,
        punycode_score
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

    brand_typo_combination = (
        similarity_score >= 20
        and typo_score >= 7
    )

    if brand_typo_combination:
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
        min(
            unicode_score,
            25
        )
        + min(
            suspicious_name_score,
            35
        )
        + min(
            tld_score,
            15
        )
        + min(
            domain_age_score,
            15
        )
    )

    domain_score = min(
        domain_score,
        45
    )

    add_reason(
        reasons,
        homograph_score > 0,
        (
            "Possible Unicode homograph "
            "attack detected."
        )
    )

    add_reason(
        reasons,
        punycode_score > 0,
        "Punycode was detected in the domain."
    )

    add_reason(
        reasons,
        entropy_score >= 8,
        (
            "The domain name appears "
            "randomly generated."
        )
    )

    add_reason(
        reasons,
        typo_score >= 7,
        (
            "The domain contains possible "
            "typosquatting patterns."
        )
    )

    add_reason(
        reasons,
        similarity_score >= 6,
        (
            "The domain resembles common "
            "phishing terminology."
        )
    )

    add_reason(
        reasons,
        brand_typo_combination,
        (
            "Brand impersonation and typosquatting "
            "were detected together."
        )
    )

    add_reason(
        reasons,
        tld_score > 0,
        (
            "The domain uses a frequently abused "
            "top-level domain."
        )
    )

    add_reason(
        reasons,
        domain_age_score > 0,
        "The domain is newly registered."
    )

    # ======================================================
    # NETWORK AND DISCLOSURE BEHAVIOUR
    # Maximum contribution: 20
    # ======================================================

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
        min(
            redirect_score,
            15
        )
        + min(
            header_score,
            2
        )
        + min(
            favicon_score,
            2
        )
        + min(
            robots_score,
            4
        )
        + min(
            sitemap_score,
            4
        )
    )

    network_score = min(
        network_score,
        20
    )

    add_reason(
        reasons,
        redirect_score >= 10,
        (
            "The website performs multiple "
            "or suspicious redirects."
        )
    )

    add_reason(
        reasons,
        favicon_score > 0,
        (
            "The favicon is loaded from "
            "an external domain."
        )
    )

    add_reason(
        reasons,
        robots_score >= 2,
        (
            "Sensitive paths were disclosed "
            "in robots.txt."
        )
    )

    add_reason(
        reasons,
        sitemap_score >= 4,
        (
            "Sensitive URLs were disclosed "
            "in the sitemap."
        )
    )

    # ======================================================
    # PAGE CONTENT AND BEHAVIOUR
    # Maximum contribution: 35
    # ======================================================

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
        min(
            javascript_score,
            20
        )
        + min(
            form_score,
            25
        )
        + min(
            content_score,
            18
        )
    )

    content_behaviour_score = min(
        content_behaviour_score,
        35
    )

    add_reason(
        reasons,
        javascript_score >= 8,
        (
            "Suspicious JavaScript behaviour "
            "was detected."
        )
    )

    add_reason(
        reasons,
        form_score >= 8,
        (
            "Suspicious form behaviour "
            "was detected."
        )
    )

    add_reason(
        reasons,
        content_score >= 8,
        (
            "The page contains suspicious "
            "phishing language."
        )
    )

    # ======================================================
    # COMBINE CATEGORY SCORES
    # ======================================================

    raw_score = (
        structure_score
        + strong_score
        + domain_score
        + network_score
        + content_behaviour_score
    )

    active_categories = sum([
        structure_score >= 12,
        strong_score >= 12,
        domain_score >= 12,
        network_score >= 10,
        content_behaviour_score >= 12
    ])

    if active_categories >= 3:
        raw_score += 10

    elif active_categories == 2:
        raw_score += 5

    if brand_typo_combination:
        raw_score += 12

    risk_score = clamp(
        raw_score
    )

    # ======================================================
    # VERDICT
    # ======================================================

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
            (
                "No major suspicious indicators "
                "were detected."
            )
        )

    return (
        risk_score,
        verdict,
        reasons
    )


def calculate_legacy_risk(
    https,
    ip_found,
    keyword_count,
    length_score,
    subdomain_score,
    at_score,
    shortener_score,
    hyphen_score,
    domain_age_score,
    tld_score
):
    """
    Temporary compatibility function for
    older app.py code.

    Returns:
        risk_score,
        verdict,
        reasons
    """

    score = 0
    reasons = []

    if not https:
        score += 20

        reasons.append(
            "The URL does not use HTTPS."
        )

    if ip_found:
        score += 20

        reasons.append(
            (
                "The URL uses an IP address "
                "instead of a domain."
            )
        )

    if keyword_count == 1:
        score += 4

        reasons.append(
            "One suspicious keyword was detected."
        )

    elif keyword_count == 2:
        score += 8

        reasons.append(
            (
                "Multiple suspicious keywords "
                "were detected."
            )
        )

    elif keyword_count >= 3:
        score += 14

        reasons.append(
            "Many suspicious keywords were detected."
        )

    if length_score > 0:
        score += min(
            length_score,
            8
        )

        reasons.append(
            "The URL is longer than normal."
        )

    if subdomain_score > 0:
        score += min(
            subdomain_score,
            8
        )

        if subdomain_score >= 6:
            reasons.append(
                (
                    "The URL contains multiple "
                    "subdomains."
                )
            )

    if at_score > 0:
        score += min(
            at_score,
            20
        )

        reasons.append(
            "The URL contains an @ symbol."
        )

    if shortener_score > 0:
        score += min(
            shortener_score,
            15
        )

        reasons.append(
            (
                "A URL-shortening service "
                "was detected."
            )
        )

    if hyphen_score > 0:
        score += min(
            hyphen_score,
            6
        )

    if domain_age_score > 0:
        score += min(
            domain_age_score,
            15
        )

        reasons.append(
            "The domain is newly registered."
        )

    if tld_score > 0:
        score += min(
            tld_score,
            15
        )

        reasons.append(
            (
                "The domain uses a frequently abused "
                "top-level domain."
            )
        )

    score = clamp(
        score
    )

    if score <= 15:
        verdict = "Safe"

    elif score <= 30:
        verdict = "Low Risk"

    elif score <= 50:
        verdict = "Medium Risk"

    elif score <= 75:
        verdict = "High Risk"

    else:
        verdict = "Critical"

    if not reasons:
        reasons.append(
            (
                "No major suspicious indicators "
                "were detected."
            )
        )

    return (
        score,
        verdict,
        reasons
    )


def calculate_risk(*args):
    """
    Supports two calling styles.

    New Detection Manager usage:

        calculate_risk(results)

    Temporary legacy usage:

        calculate_risk(
            https,
            ip_found,
            keyword_count,
            length_score,
            subdomain_score,
            at_score,
            shortener_score,
            hyphen_score,
            domain_age_score,
            tld_score
        )
    """

    if (
        len(args) == 1
        and isinstance(
            args[0],
            dict
        )
    ):
        return calculate_from_results(
            args[0]
        )

    if len(args) == 10:
        return calculate_legacy_risk(
            *args
        )

    raise TypeError(
        (
            "calculate_risk expects either one "
            "results dictionary or the 10 legacy "
            "checker arguments."
        )
    )