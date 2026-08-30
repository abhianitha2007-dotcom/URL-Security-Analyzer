from analyzer.exceptions import AnalysisIncompleteError
from analyzer.scoring_policy import load_scoring_policy


MAX_SCORE = 100


def clamp(value, minimum=0, maximum=MAX_SCORE):
    return max(minimum, min(int(round(value)), maximum))


def get_dict(results, key):
    value = results.get(key, {})
    return value if isinstance(value, dict) else {}


def get_int(data, key, default=0):
    if not isinstance(data, dict):
        return default
    try:
        return int(data.get(key, default) or default)
    except (TypeError, ValueError):
        return default


def get_float(data, key, default=0.0):
    if not isinstance(data, dict):
        return default
    try:
        return float(data.get(key, default) or default)
    except (TypeError, ValueError):
        return default


def get_score(results, key):
    return get_int(get_dict(results, key), "score")


def add_reason(reasons, condition, message):
    if condition and message not in reasons:
        reasons.append(message)


def ensure_complete(results):
    scan_status = get_dict(results, "scan_status")
    if scan_status and not scan_status.get("complete", False):
        raise AnalysisIncompleteError(
            scan_status.get(
                "message",
                "The analysis could not be completed. Please retry.",
            ),
            scan_status.get("failed_checks", ()),
        )


def verdict_for(score, policy):
    for band in policy["verdict_bands"]:
        if score <= int(band["maximum"]):
            return band["verdict"]
    return "Critical"


def reputation_evidence(results, reasons, policy):
    intelligence = get_dict(results, "threat_intelligence")
    if not intelligence.get("report_found", False):
        return 0, 0

    malicious = get_int(intelligence, "malicious")
    suspicious = get_int(intelligence, "suspicious")
    score = 0
    floor = 0
    floors = policy["reputation_floors"]
    weights = policy["weights"]["reputation"]

    if malicious >= 10:
        score = weights["ten_malicious"]
        floor = floors["ten_malicious"]
    elif malicious >= 5:
        score = weights["five_malicious"]
        floor = floors["five_malicious"]
    elif malicious >= 3:
        score = weights["three_malicious"]
        floor = floors["three_malicious"]
    elif malicious == 2:
        score = weights["two_malicious"]
        floor = floors["two_malicious"]
    elif malicious == 1 and suspicious >= 2:
        score = weights["one_malicious_two_suspicious"]
        floor = weights["two_malicious"]
    elif malicious == 1 and suspicious == 1:
        score = weights["one_malicious_one_suspicious"]
    elif suspicious >= 5:
        score = weights["five_suspicious"]
        floor = weights["two_malicious"]
    elif suspicious >= 2:
        score = weights["two_suspicious"]
    elif suspicious == 1:
        score = 0

    if malicious == 1 and suspicious == 0:
        add_reason(
            reasons,
            True,
            (
                "VirusTotal reports one isolated malicious classification. "
                "It is recorded as inconclusive and does not change the score."
            ),
        )
    elif malicious > 0:
        add_reason(
            reasons,
            True,
            f"VirusTotal reports {malicious} malicious classification(s).",
        )

    if suspicious > 0:
        add_reason(
            reasons,
            True,
            f"VirusTotal reports {suspicious} suspicious classification(s).",
        )

    return min(score, policy["category_caps"]["reputation"]), floor


def contextual_support(results, policy):
    thresholds = policy["thresholds"]
    form_issues = set(get_dict(results, "forms").get("issues", []))
    mixed = get_dict(results, "mixed_content")
    intelligence = get_dict(results, "threat_intelligence")
    hyphens = get_dict(results, "hyphens")

    signals = {
        "http": not get_dict(results, "https").get("detected", False),
        "ip": get_dict(results, "ip_address").get("detected", False),
        "at_symbol": get_score(results, "at_symbol") > 0,
        "dangerous_file": get_score(results, "file_extension") >= thresholds["dangerous_file"],
        "nonstandard_port": get_score(results, "port") >= thresholds["nonstandard_port"],
        "new_domain": get_dict(results, "domain_age").get(
            "confirmed_new", False
        ),
        "multiple_hyphens": get_int(hyphens, "count") >= 2,
        "homograph": get_score(results, "homograph") >= thresholds["homograph"],
        "cross_domain_form": "cross_domain_form_action" in form_issues,
        "unsafe_password_form": "password_sent_using_get" in form_issues,
        "suspicious_redirect": get_score(results, "redirects") >= thresholds["suspicious_redirect"],
        "https_downgrade": bool(mixed.get("downgraded_to_http", False)),
        "reputation": (
            get_int(intelligence, "malicious") >= 2
            or get_int(intelligence, "suspicious") >= 2
        ),
    }
    return signals


def lexical_evidence(results, support, reasons, policy):
    language = get_dict(results, "keywords")
    probability = get_float(language, "probability")
    high = float(policy["lexical"]["high_probability"])
    elevated = float(policy["lexical"]["elevated_probability"])
    support_count = sum(support.values())

    if probability >= high:
        score = int(policy["lexical"]["high_score"])
    elif (
        probability >= elevated
        and support_count >= int(policy["lexical"]["minimum_support"])
    ):
        score = int(policy["lexical"]["elevated_score"])
    else:
        score = 0

    add_reason(
        reasons,
        score > 0,
        "The versioned URL-language model detected a risky lexical pattern.",
    )
    return score


def structure_evidence(results, support, lexical_score, reasons, policy):
    score = 0
    weights = policy["weights"]["structure"]
    thresholds = policy["thresholds"]
    at_score = get_score(results, "at_symbol")
    port_score = get_score(results, "port")
    file_score = get_score(results, "file_extension")
    email_score = get_score(results, "email_address")
    homograph_score = get_score(results, "homograph")
    punycode_score = get_score(results, "punycode")

    if support["ip"]:
        score += weights["ip_host"]
        add_reason(reasons, True, "The URL uses an IP address as its host.")
    if at_score > 0:
        score += min(at_score, weights["at_symbol_cap"])
        add_reason(reasons, True, "The URL contains a deceptive @ symbol.")
    if port_score >= thresholds["nonstandard_port"]:
        score += min(port_score, weights["port_cap"])
        add_reason(reasons, True, "The URL uses a suspicious non-standard port.")
    if file_score >= thresholds["dangerous_file"]:
        score += min(file_score, weights["dangerous_file_cap"])
        add_reason(reasons, True, "The URL targets a potentially dangerous file.")
    if email_score > 0 and (lexical_score > 0 or support["reputation"]):
        score += min(email_score, weights["email_cap"])
        add_reason(reasons, True, "The URL embeds an email address.")
    if homograph_score >= thresholds["homograph"]:
        score += min(max(homograph_score, punycode_score), weights["homograph_cap"])
        add_reason(reasons, True, "A possible Unicode homograph attack was detected.")

    if support["http"] and (lexical_score > 0 or support["reputation"]):
        score += weights["corroborated_http"]
        add_reason(
            reasons,
            True,
            "The suspicious context is delivered without HTTPS protection.",
        )

    return min(score, policy["category_caps"]["structure"])


def domain_evidence(results, support, lexical_score, reasons, policy):
    score = 0
    weights = policy["weights"]["domain"]
    thresholds = policy["thresholds"]
    typo_score = get_score(results, "typosquatting")
    entropy_score = get_score(results, "entropy")

    if typo_score >= thresholds["typosquatting"] and lexical_score > 0:
        score += min(typo_score, weights["typosquatting_cap"])
        add_reason(reasons, True, "The hostname contains typosquatting patterns.")

    if entropy_score >= thresholds["unusual_entropy"] and lexical_score > 0:
        score += min(entropy_score, weights["entropy_cap"])
        add_reason(reasons, True, "The hostname has an unusually random structure.")

    if support["new_domain"] and (
        lexical_score > 0
        or support["reputation"]
        or support["homograph"]
        or support["cross_domain_form"]
    ):
        score += min(
            get_score(results, "domain_age") or weights["new_domain_cap"],
            weights["new_domain_cap"],
        )
        add_reason(reasons, True, "The domain is newly registered.")

    if lexical_score > 0 and support["multiple_hyphens"]:
        score += weights["multiple_hyphens"]
        add_reason(
            reasons,
            True,
            "Multiple separators reinforce the risky hostname pattern.",
        )

    return min(score, policy["category_caps"]["domain"])


def behavior_evidence(results, lexical_score, reasons, policy):
    score = 0
    weights = policy["weights"]["behavior"]
    thresholds = policy["thresholds"]
    form = get_dict(results, "forms")
    form_issues = set(form.get("issues", []))
    javascript_score = get_score(results, "javascript")
    redirect_score = get_score(results, "redirects")
    mixed = get_dict(results, "mixed_content")

    if "cross_domain_form_action" in form_issues:
        score += weights["cross_domain_form"]
        add_reason(reasons, True, "A form submits data to a different domain.")
    if "password_sent_using_get" in form_issues:
        score += weights["password_get"]
        add_reason(reasons, True, "A password form sends credentials in the URL.")
    if javascript_score >= thresholds["high_javascript"]:
        score += min(javascript_score, weights["javascript_cap"])
        add_reason(reasons, True, "High-risk JavaScript behaviour was detected.")
    if redirect_score >= thresholds["suspicious_redirect"]:
        score += min(redirect_score, weights["redirect_cap"])
        add_reason(reasons, True, "The destination uses a suspicious redirect chain.")
    if mixed.get("downgraded_to_http", False):
        score += weights["https_downgrade"]
        add_reason(reasons, True, "The request was downgraded from HTTPS to HTTP.")

    return min(score, policy["category_caps"]["behavior"])


def calculate_from_results(results):
    ensure_complete(results)
    policy = load_scoring_policy()
    reasons = []
    support = contextual_support(results, policy)
    reputation_score, reputation_floor = reputation_evidence(
        results, reasons, policy
    )
    lexical_score = lexical_evidence(results, support, reasons, policy)
    structure_score = structure_evidence(
        results, support, lexical_score, reasons, policy
    )
    domain_score = domain_evidence(
        results, support, lexical_score, reasons, policy
    )
    behavior_score = behavior_evidence(
        results, lexical_score, reasons, policy
    )

    category_scores = {
        "lexical": lexical_score,
        "structure": structure_score,
        "domain": domain_score,
        "behavior": behavior_score,
        "reputation": reputation_score,
    }
    raw_score = sum(category_scores.values())
    minimum_category_score = int(
        policy["corroboration_bonus"]["minimum_category_score"]
    )
    active_categories = sum(
        score >= minimum_category_score for score in category_scores.values()
    )
    if active_categories >= 3:
        raw_score += int(policy["corroboration_bonus"]["three_categories"])
    elif active_categories == 2:
        raw_score += int(policy["corroboration_bonus"]["two_categories"])

    risk_score = max(clamp(raw_score), int(reputation_floor))
    if support["https_downgrade"]:
        risk_score = max(
            risk_score,
            int(policy["minimum_risk"]["https_downgrade"]),
        )
    risk_score = clamp(risk_score)
    verdict = verdict_for(risk_score, policy)

    if not reasons:
        reasons.append("No corroborated phishing or malware evidence was detected.")

    return risk_score, verdict, reasons


def calculate_posture(results):
    policy = load_scoring_policy()["posture"]
    deductions = policy["deductions"]
    score = 100
    issues = []

    if not get_dict(results, "https").get("detected", False):
        score -= deductions["http"]
        issues.append("The connection does not use HTTPS.")

    ssl = get_dict(results, "ssl")
    ssl_status = str(ssl.get("status", "")).lower()
    if ssl_status and not any(
        term in ssl_status for term in ("valid", "not applicable", "http")
    ):
        score -= deductions["invalid_tls"]
        issues.append("The TLS certificate could not be validated.")

    missing_headers = get_dict(results, "security_headers").get("missing", [])
    if not missing_headers:
        missing_headers = get_dict(results, "security_headers").get(
            "missing_headers", []
        )
    if isinstance(missing_headers, list) and missing_headers:
        deduction = min(
            len(missing_headers) * deductions["missing_header_each"],
            deductions["missing_header_cap"],
        )
        score -= deduction
        issues.append(f"{len(missing_headers)} recommended security header(s) are missing.")

    cookie_issues = get_dict(results, "cookie_security").get("issues", [])
    if cookie_issues:
        score -= min(
            len(cookie_issues) * deductions["cookie_issue_each"],
            deductions["cookie_issue_cap"],
        )
        issues.extend(str(item) for item in cookie_issues[:3])

    cors = get_dict(results, "cors")
    if cors.get("origin_reflection") and cors.get("allow_credentials"):
        score -= deductions["cors_reflection_credentials"]
        issues.append("CORS reflects arbitrary origins with credentials.")
    elif cors.get("origin_reflection"):
        score -= deductions["cors_reflection"]
        issues.append("CORS reflects arbitrary origins.")

    mixed = get_dict(results, "mixed_content")
    if mixed.get("downgraded_to_http"):
        score -= deductions["https_downgrade"]
    elif get_int(mixed, "active_count"):
        score -= min(
            deductions["active_mixed_base"] + get_int(mixed, "active_count"),
            deductions["active_mixed_cap"],
        )
        issues.append("The page loads active content over HTTP.")

    outdated = get_dict(results, "response_headers").get(
        "outdated_software", []
    )
    if outdated:
        score -= min(
            len(outdated) * deductions["outdated_software_each"],
            deductions["outdated_software_cap"],
        )
        issues.append("Outdated server technology was disclosed.")

    score = clamp(score)
    grade = next(
        item["grade"]
        for item in policy["grades"]
        if score >= int(item["minimum"])
    )
    return {"score": score, "grade": grade, "issues": issues}


def calculate_assessment(results):
    risk_score, verdict, reasons = calculate_from_results(results)
    policy = load_scoring_policy()
    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons,
        "posture": calculate_posture(results),
        "engine_version": policy["engine_version"],
        "policy_version": policy["policy_version"],
        "model_version": get_dict(results, "keywords").get(
            "model_version", "unknown"
        ),
    }


def calculate_risk(results):
    if not isinstance(results, dict):
        raise TypeError(
            "calculate_risk expects the Detection Manager results dictionary."
        )
    return calculate_from_results(results)
