import unittest

from analyzer.risk_engine import calculate_risk


def clean_results():
    return {
        "https": {
            "detected": True,
            "score": 0,
            "status": "HTTPS Detected"
        },
        "ip_address": {
            "detected": False,
            "score": 0,
            "status": "Domain Name Used"
        },
        "keywords": {
            "count": 0,
            "matches": [],
            "score": 0
        },
        "mixed_content": {
            "downgraded_to_http": False,
            "active_count": 0,
            "passive_count": 0,
            "score": 0
        },
        "threat_intelligence": {
            "checked": False,
            "report_found": False,
            "submitted": False,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "score": 0
        }
    }


class RiskEngineRegressionTests(unittest.TestCase):

    def test_clean_url_is_safe(self):
        results = clean_results()

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertEqual(risk_score, 0)
        self.assertEqual(verdict, "Safe")
        self.assertIn(
            "No major suspicious indicators were detected.",
            reasons
        )

    def test_single_virustotal_detection_is_weak_evidence(self):
        results = clean_results()

        results["threat_intelligence"] = {
            "checked": True,
            "report_found": True,
            "submitted": False,
            "malicious": 1,
            "suspicious": 0,
            "harmless": 62,
            "undetected": 29,
            "total_engines": 92,
            "score": 15
        }

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertEqual(risk_score, 5)
        self.assertEqual(verdict, "Safe")

        self.assertTrue(
            any(
                "isolated malicious classification" in reason.lower()
                for reason in reasons
            )
        )

    def test_single_suspicious_detection_is_low_weight(self):
        results = clean_results()

        results["threat_intelligence"] = {
            "checked": True,
            "report_found": True,
            "submitted": False,
            "malicious": 0,
            "suspicious": 1,
            "harmless": 70,
            "undetected": 20,
            "total_engines": 91,
            "score": 15
        }

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertEqual(risk_score, 3)
        self.assertEqual(verdict, "Safe")

    def test_one_malicious_with_multiple_suspicious_signals(self):
        results = clean_results()

        results["threat_intelligence"] = {
            "checked": True,
            "report_found": True,
            "submitted": False,
            "malicious": 1,
            "suspicious": 2,
            "harmless": 60,
            "undetected": 29,
            "total_engines": 92,
            "score": 25
        }

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertGreaterEqual(risk_score, 35)
        self.assertEqual(verdict, "Medium Risk")

    def test_two_malicious_engines_force_high_risk(self):
        results = clean_results()

        results["threat_intelligence"] = {
            "checked": True,
            "report_found": True,
            "submitted": False,
            "malicious": 2,
            "suspicious": 0,
            "harmless": 60,
            "undetected": 30,
            "total_engines": 92,
            "score": 30
        }

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertGreaterEqual(risk_score, 55)
        self.assertEqual(verdict, "High Risk")

    def test_three_malicious_engines_force_high_risk(self):
        results = clean_results()

        results["threat_intelligence"] = {
            "checked": True,
            "report_found": True,
            "submitted": False,
            "malicious": 3,
            "suspicious": 0,
            "harmless": 59,
            "undetected": 30,
            "total_engines": 92,
            "score": 35
        }

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertGreaterEqual(risk_score, 60)
        self.assertEqual(verdict, "High Risk")

    def test_ten_malicious_engines_force_critical(self):
        results = clean_results()

        results["threat_intelligence"] = {
            "checked": True,
            "report_found": True,
            "submitted": False,
            "malicious": 10,
            "suspicious": 0,
            "harmless": 50,
            "undetected": 32,
            "total_engines": 92,
            "score": 45
        }

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertGreaterEqual(risk_score, 80)
        self.assertEqual(verdict, "Critical")

    def test_http_url_is_not_safe(self):
        results = clean_results()

        results["https"]["detected"] = False

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertGreaterEqual(risk_score, 20)
        self.assertEqual(verdict, "Low Risk")

        self.assertIn(
            "The URL does not use HTTPS.",
            reasons
        )

    def test_https_downgrade_has_minimum_risk(self):
        results = clean_results()

        results["mixed_content"] = {
            "downgraded_to_http": True,
            "active_count": 0,
            "passive_count": 0,
            "score": 8
        }

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertGreaterEqual(risk_score, 20)
        self.assertEqual(verdict, "Low Risk")


if __name__ == "__main__":
    unittest.main()