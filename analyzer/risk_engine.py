def calculate_risk(
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
    Calculates URL security risk score.

    Returns:
        risk_score (0-100)
        verdict
    """


    score = 0


    # -------------------------
    # HTTPS Check
    # -------------------------

    if not https:
        score += 15



    # -------------------------
    # IP Address Detection
    # -------------------------

    if ip_found:
        score += 25



    # -------------------------
    # Suspicious Keywords
    # -------------------------

    keyword_risk = keyword_count * 8

    # Maximum keyword contribution
    score += min(
        keyword_risk,
        20
    )



    # -------------------------
    # URL Length
    # -------------------------

    score += length_score



    # -------------------------
    # Subdomain Risk
    # -------------------------

    score += subdomain_score



    # -------------------------
    # @ Symbol
    # -------------------------

    score += at_score



    # -------------------------
    # URL Shortener
    # -------------------------

    score += shortener_score



    # -------------------------
    # Hyphen Usage
    # -------------------------

    score += hyphen_score



    # -------------------------
    # Domain Age
    # -------------------------

    score += domain_age_score



    # -------------------------
    # TLD Reputation
    # -------------------------

    score += tld_score



    # Keep range 0-100

    score = min(
        score,
        100
    )



    # -------------------------
    # Verdict
    # -------------------------

    if score <= 25:

        verdict = "🟢 Safe"


    elif score <= 60:

        verdict = "🟡 Suspicious"


    else:

        verdict = "🔴 High Risk"



    return score, verdict