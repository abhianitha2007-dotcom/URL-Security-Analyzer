from analyzer.risk_engine import calculate_risk


def blank_results():
    """
    Create a clean synthetic Detection Manager result.

    This allows us to test the risk engine without
    making network requests or visiting malicious sites.
    """

    return {
        "https": {
            "detected": True
        },

        "ip_address": {
            "detected": False
        },

        "keywords": {
            "count": 0
        },

        "url_length": {
            "score": 0
        },

        "subdomains": {
            "score": 0
        },

        "hyphens": {
            "score": 0
        },

        "query_parameters": {
            "score": 0
        },

        "email_address": {
            "score": 0
        },

        "at_symbol": {
            "score": 0
        },

        "shortener": {
            "score": 0
        },

        "port": {
            "score": 0
        },

        "file_extension": {
            "score": 0
        },

        "file_exposure": {
            "score": 0
        },

        "homograph": {
            "score": 0
        },

        "punycode": {
            "score": 0
        },

        "entropy": {
            "score": 0
        },

        "typosquatting": {
            "score": 0
        },

        "domain_similarity": {
            "score": 0
        },

        "tld": {
            "score": 0
        },

        "domain_age": {
            "score": 0
        },

        "redirects": {
            "score": 0
        },

        "security_headers": {
            "score": 0
        },

        "favicon": {
            "score": 0
        },

        "robots": {
            "score": 0
        },

        "sitemap": {
            "score": 0
        },

        "javascript": {
            "score": 0
        },

        "forms": {
            "score": 0
        },

        "content": {
            "score": 0
        },

        "cookie_security": {
            "score": 0
        },

        "cors": {
            "score": 0,
            "origin_reflection": False,
            "allow_credentials": False,
            "allow_origin": ""
        },

        "mixed_content": {
            "score": 0,
            "downgraded_to_http": False,
            "active_count": 0,
            "passive_count": 0
        },

        "threat_intelligence": {
            "checked": True,
            "report_found": True,
            "submitted": False,

            "malicious": 0,
            "suspicious": 0,
            "harmless": 80,
            "total_engines": 90,

            "score": 0
        }
    }


def run_test(name, modify):
    results = blank_results()

    modify(results)

    score, verdict, reasons = calculate_risk(
        results
    )

    print("=" * 70)

    print(name)

    print(
        f"Risk Score : {score}"
    )

    print(
        f"Verdict    : {verdict}"
    )

    print("Reasons:")

    for reason in reasons:
        print(
            f" - {reason}"
        )

    print()


# =========================================================
# TEST 1
# CLEAN WEBSITE
# =========================================================

run_test(
    "TEST 1 - Completely Clean Website",
    lambda r: None
)


# =========================================================
# TEST 2
# HTTP ONLY
# =========================================================

run_test(
    "TEST 2 - HTTP Website",
    lambda r: r["https"].update({
        "detected": False
    })
)


# =========================================================
# TEST 3
# DIRECT IP + HTTP
# =========================================================

def direct_ip_http(r):

    r["https"]["detected"] = False

    r["ip_address"]["detected"] = True


run_test(
    "TEST 3 - HTTP + Direct IP Address",
    direct_ip_http
)


# =========================================================
# TEST 4
# SHORTENER ONLY
# =========================================================

run_test(
    "TEST 4 - URL Shortener Only",
    lambda r: r["shortener"].update({
        "score": 15
    })
)


# =========================================================
# TEST 5
# PHISHING-STYLE URL STRUCTURE
# =========================================================

def phishing_structure(r):

    r["https"]["detected"] = False

    r["keywords"]["count"] = 4

    r["url_length"]["score"] = 10

    r["subdomains"]["score"] = 15

    r["hyphens"]["score"] = 20


run_test(
    "TEST 5 - Strong Suspicious URL Structure",
    phishing_structure
)


# =========================================================
# TEST 6
# DOMAIN IMPERSONATION PATTERN
# =========================================================

def domain_impersonation(r):

    r["domain_similarity"]["score"] = 20

    r["typosquatting"]["score"] = 10


run_test(
    "TEST 6 - Similarity + Typosquatting",
    domain_impersonation
)


# =========================================================
# TEST 7
# NEW DOMAIN + BAD TLD
# =========================================================

def new_bad_domain(r):

    r["domain_age"]["score"] = 20

    r["tld"]["score"] = 15


run_test(
    "TEST 7 - New Domain + Abused TLD",
    new_bad_domain
)


# =========================================================
# TEST 8
# COOKIE HARDENING ONLY
# =========================================================

run_test(
    "TEST 8 - Cookie Issue Only",
    lambda r: r["cookie_security"].update({
        "score": 2
    })
)


# =========================================================
# TEST 9
# SERIOUS CORS ISSUE
# =========================================================

def dangerous_cors(r):

    r["cors"].update({
        "origin_reflection": True,
        "allow_credentials": True,
        "allow_origin": "https://evil-example.test"
    })


run_test(
    "TEST 9 - Arbitrary CORS Origin + Credentials",
    dangerous_cors
)


# =========================================================
# TEST 10
# HTTPS DOWNGRADE
# =========================================================

def https_downgrade(r):

    r["mixed_content"].update({
        "downgraded_to_http": True
    })


run_test(
    "TEST 10 - HTTPS Downgrade",
    https_downgrade
)


# =========================================================
# TEST 11
# ONE VIRUSTOTAL SUSPICIOUS
# =========================================================

def one_vt_suspicious(r):

    r["threat_intelligence"].update({
        "suspicious": 1,
        "score": 3
    })


run_test(
    "TEST 11 - One VirusTotal Suspicious Signal",
    one_vt_suspicious
)


# =========================================================
# TEST 12
# TWO VIRUSTOTAL MALICIOUS
# =========================================================

def two_vt_malicious(r):

    r["threat_intelligence"].update({
        "malicious": 2,
        "score": 24
    })


run_test(
    "TEST 12 - Two VirusTotal Malicious Detections",
    two_vt_malicious
)


# =========================================================
# TEST 13
# FIVE VIRUSTOTAL MALICIOUS
# =========================================================

def five_vt_malicious(r):

    r["threat_intelligence"].update({
        "malicious": 5,
        "score": 35
    })


run_test(
    "TEST 13 - Five VirusTotal Malicious Detections",
    five_vt_malicious
)


# =========================================================
# TEST 14
# TEN VIRUSTOTAL MALICIOUS
# =========================================================

def ten_vt_malicious(r):

    r["threat_intelligence"].update({
        "malicious": 10,
        "score": 40
    })


run_test(
    "TEST 14 - Ten VirusTotal Malicious Detections",
    ten_vt_malicious
)


# =========================================================
# TEST 15
# MULTI-LAYER PHISHING
# =========================================================

def multilayer_phishing(r):

    r["https"]["detected"] = False

    r["keywords"]["count"] = 4

    r["url_length"]["score"] = 10

    r["subdomains"]["score"] = 15


    r["domain_similarity"]["score"] = 20

    r["typosquatting"]["score"] = 10

    r["domain_age"]["score"] = 20

    r["tld"]["score"] = 15


    r["forms"]["score"] = 15

    r["content"]["score"] = 12


    r["threat_intelligence"].update({
        "malicious": 5,
        "score": 35
    })


run_test(
    "TEST 15 - Multi-Layer Phishing Scenario",
    multilayer_phishing
)