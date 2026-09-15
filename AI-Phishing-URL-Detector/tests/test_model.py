"""
Unit tests for Machine Learning Inference Engine.
"""

import unittest
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.models.predict import PhishingPredictor


class TestModelInference(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.predictor = PhishingPredictor()

    def test_benign_prediction(self):
        """Standard high-reputation domains should be flagged Legitimate."""
        res = self.predictor.predict("https://github.com/torvalds/linux")
        self.assertIn("label", res)
        self.assertEqual(res["label"], "Legitimate")
        self.assertFalse(res["is_phishing"])
        self.assertLess(res["risk_score"], 40)

    def test_phishing_prediction(self):
        """High-risk spoofing URLs should be flagged Phishing."""
        res = self.predictor.predict("http://paypal-verify-account.attacker.xyz/login.php")
        self.assertEqual(res["label"], "Phishing")
        self.assertTrue(res["is_phishing"])
        self.assertGreater(res["risk_score"], 60)
        self.assertTrue(len(res["threat_indicators"]) > 0)

    def test_batch_prediction(self):
        """Batch processing should analyze every valid URL in the input list."""
        urls = [
            "https://google.com",
            "http://192.168.1.1/banking/login",
            "https://wikipedia.org"
        ]
        results = self.predictor.predict_batch(urls)
        self.assertEqual(len(results), 3)
        for r in results:
            self.assertIn("risk_score", r)
            self.assertTrue(0.0 <= r["risk_score"] <= 100.0)


if __name__ == "__main__":
    unittest.main()
