def calculate_risk(
    https,
    ip_found,
    keyword_count,
    length_score,
    subdomain_score,
    at_score,
    shortener_score,
    hyphen_score,
    domain_age_score
):
    """
    Calculates the overall risk score.

    Returns:
        score (0-100)
        verdict
    """

    score = 0

    # HTTP instead of HTTPS
    if not https:
        score += 40

    # IP address used instead of domain
    if ip_found:
        score += 40

    # Suspicious keywords
    score += keyword_count * 10

    # URL length
    score += length_score

    # Too many subdomains
    score += subdomain_score

    # @ symbol
    score += at_score

    # URL shortener
    score += shortener_score

    # Hyphens
    score += hyphen_score

    # Domain age
    score += domain_age_score

    # Maximum score = 100
    score = min(score, 100)

    if score <= 20:
        verdict = "🟢 Safe"

    elif score <= 60:
        verdict = "🟡 Suspicious"

    else:
        verdict = "🔴 High Risk"

    return score, verdict