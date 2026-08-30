import unittest

from analyzer.detection_manager import _offline_checks
from analyzer.exceptions import AnalysisIncompleteError
from analyzer.risk_engine import calculate_posture, calculate_risk


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

    @staticmethod
    def complete_url_results(url, newly_registered=False):
        results = _offline_checks(url)
        results.update({
            "scan_status": {"complete": True},
            "domain_age": {
                "confirmed_new": newly_registered,
                "score": 20 if newly_registered else 0,
            },
            "forms": {"issues": [], "score": 0},
            "redirects": {"score": 0},
            "javascript": {"score": 0},
            "mixed_content": {"downgraded_to_http": False},
            "threat_intelligence": {
                "checked": True,
                "report_found": False,
                "malicious": 0,
                "suspicious": 0,
            },
        })
        return results

    def test_clean_url_is_safe(self):
        results = clean_results()

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertEqual(risk_score, 0)
        self.assertEqual(verdict, "Safe")
        self.assertIn(
            "No corroborated phishing or malware evidence was detected.",
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

        self.assertEqual(risk_score, 0)
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

        self.assertEqual(risk_score, 0)
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

    def test_one_malicious_and_one_suspicious_is_not_called_safe(self):
        results = clean_results()
        results["threat_intelligence"] = {
            "checked": True,
            "report_found": True,
            "malicious": 1,
            "suspicious": 1,
        }

        risk_score, verdict, _ = calculate_risk(results)

        self.assertEqual(risk_score, 8)
        self.assertEqual(verdict, "Low Risk")

    def test_email_in_url_alone_does_not_create_threat_risk(self):
        results = clean_results()
        results["email_address"] = {"score": 10}

        risk_score, verdict, _ = calculate_risk(results)

        self.assertEqual(risk_score, 0)
        self.assertEqual(verdict, "Safe")

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

    def test_http_is_a_posture_issue_without_threat_evidence(self):
        results = clean_results()

        results["https"]["detected"] = False

        risk_score, verdict, reasons = calculate_risk(results)

        self.assertEqual(risk_score, 0)
        self.assertEqual(verdict, "Safe")

        posture = calculate_posture(results)
        self.assertLess(posture["score"], 100)
        self.assertIn(
            "The connection does not use HTTPS.",
            posture["issues"]
        )

    def test_lexical_probability_requires_corroboration(self):
        results = clean_results()
        results["keywords"] = {
            "probability": 0.75,
            "matches": ["login"],
            "count": 1,
            "score": 0,
        }

        risk_score, verdict, _ = calculate_risk(results)

        self.assertEqual(risk_score, 0)
        self.assertEqual(verdict, "Safe")

    def test_incomplete_analysis_never_returns_a_score(self):
        results = clean_results()
        results["scan_status"] = {
            "complete": False,
            "message": "Analysis could not be completed.",
            "failed_checks": ["dns"],
        }

        with self.assertRaises(AnalysisIncompleteError):
            calculate_risk(results)

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

    def test_official_login_path_is_not_a_threat_by_keyword(self):
        results = self.complete_url_results(
            "https://ssp.postmatric.karnataka.gov.in/2324/signin.aspx"
        )

        risk_score, verdict, _ = calculate_risk(results)

        self.assertEqual(risk_score, 0)
        self.assertEqual(verdict, "Safe")

    def test_contextual_phishing_domain_is_high_risk(self):
        results = self.complete_url_results(
            "https://paypal-login-security.xyz/",
            newly_registered=True,
        )

        risk_score, verdict, _ = calculate_risk(results)

        self.assertGreaterEqual(risk_score, 51)
        self.assertEqual(verdict, "High Risk")

    def test_sensitive_content_domain_is_not_malicious_by_itself(self):
        results = self.complete_url_results("https://xhamster.com/")
        results["content_warning"] = {
            "show": True,
            "type": "adult",
        }

        risk_score, verdict, _ = calculate_risk(results)

        self.assertEqual(risk_score, 0)
        self.assertEqual(verdict, "Safe")


if __name__ == "__main__":
    unittest.main()
