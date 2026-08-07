from analyzer.risk_engine import calculate_risk


def create_results(
    malicious=0,
    suspicious=0,
    threat_score=0,
    cookie_score=0
):
    """
    Create safe base results and inject
    synthetic VirusTotal values.
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

        "cookie_security": {
            "score": cookie_score
        },

        "cors": {
            "score": 0,
            "origin_reflection": False,
            "allow_credentials": False,
            "allow_origin": "Not Set"
        },

        "mixed_content": {
            "score": 0,
            "active_count": 0,
            "passive_count": 0,
            "downgraded_to_http": False
        },

        "threat_intelligence": {
            "checked": True,
            "report_found": True,
            "submitted": False,

            "malicious": malicious,
            "suspicious": suspicious,

            "harmless": 60,
            "undetected": 20,
            "total_engines": 80,

            "score": threat_score
        }
    }


tests = [

    (
        "Clean reputation",
        create_results(
            malicious=0,
            suspicious=0,
            threat_score=0
        )
    ),

    (
        "Cookie observation only",
        create_results(
            malicious=0,
            suspicious=0,
            threat_score=0,
            cookie_score=1
        )
    ),

    (
        "1 suspicious vendor",
        create_results(
            suspicious=1,
            threat_score=3
        )
    ),

    (
        "2 suspicious vendors",
        create_results(
            suspicious=2,
            threat_score=6
        )
    ),

    (
        "5 suspicious vendors",
        create_results(
            suspicious=5,
            threat_score=10
        )
    ),

    (
        "1 malicious vendor",
        create_results(
            malicious=1,
            threat_score=15
        )
    ),

    (
        "2 malicious vendors",
        create_results(
            malicious=2,
            threat_score=24
        )
    ),

    (
        "3 malicious vendors",
        create_results(
            malicious=3,
            threat_score=30
        )
    ),

    (
        "5 malicious vendors",
        create_results(
            malicious=5,
            threat_score=35
        )
    ),

    (
        "10 malicious vendors",
        create_results(
            malicious=10,
            threat_score=40
        )
    )
]


print("\nVirusTotal Risk Engine Tests")
print("=" * 65)


for name, results in tests:

    score, verdict, reasons = calculate_risk(
        results
    )

    print(f"\n{name}")

    print(
        f"Risk Score : {score}"
    )

    print(
        f"Verdict    : {verdict}"
    )

    print(
        "Reasons:"
    )

    for reason in reasons:

        print(
            f"  - {reason}"
        )


print("\n" + "=" * 65)