"""Regression tests for strict LinkShield URL-only phishing scoring."""

import unittest

from analysis.scoring import create_analysis_result
from analysis.security_checks import run_security_checks
from analysis.url_parser import parse_url


def analyze(url: str) -> dict:
    parsed = parse_url(url)
    return create_analysis_result(parsed["normalized"], run_security_checks(parsed["normalized"], parsed))


class StrictRiskAnalysisTests(unittest.TestCase):
    def assert_verdict(self, url: str, expected: str) -> None:
        self.assertEqual(analyze(url)["verdict"], expected, url)

    def test_known_safe_domains_remain_low_risk(self):
        for url in ("https://www.google.com", "https://github.com", "https://www.microsoft.com", "https://www.amazon.com"):
            self.assert_verdict(url, "Low Risk")

    def test_suspicious_urls_are_not_low_risk(self):
        self.assert_verdict("http://example-login.com", "Suspicious")
        self.assert_verdict("https://secure-account-example.com/login", "Suspicious")
        self.assert_verdict("https://example.com/login/verify", "Suspicious")

    def test_high_risk_deception_patterns(self):
        self.assertIn(analyze("http://192.168.1.10/login")["verdict"], {"High Risk", "Critical / Likely Phishing"})
        self.assertIn(analyze("https://google.com@evil-example.com/login")["verdict"], {"High Risk", "Critical / Likely Phishing"})
        self.assertIn(analyze("https://paypa1-login-security-example.com/verify")["verdict"], {"High Risk", "Critical / Likely Phishing"})

    def test_critical_combination_cannot_be_safe(self):
        result = analyze("http://google.com@192.168.1.10/login/password/verification?redirect=%2F%2Fevil.test&token=abcdef0123456789&next=login")
        self.assertEqual(result["verdict"], "Critical / Likely Phishing")
        self.assertEqual(result["score"], 100)
        self.assertTrue(any(check["category"] == "correlation" for check in result["checks"]))

    def test_encoding_shortener_and_unicode_signals(self):
        self.assertNotEqual(analyze("https://bit.ly/login?redirect=%2F%2Fevil.test")["verdict"], "Low Risk")
        self.assertIn(analyze("https://xn--paypa1-9za.example/login")["verdict"], {"High Risk", "Critical / Likely Phishing"})


if __name__ == "__main__":
    unittest.main()
