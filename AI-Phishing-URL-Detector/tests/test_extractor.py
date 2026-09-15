"""
Unit tests for FeatureExtractor.
"""

import unittest
import sys
import os

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.features.extractor import FeatureExtractor, is_ip_address, count_subdomains, calculate_shannon_entropy


class TestFeatureExtractor(unittest.TestCase):

    def test_feature_vector_dimension(self):
        """Feature vector must always have exactly 22 features."""
        url = "https://www.google.com/search?q=cybersecurity"
        vector = FeatureExtractor.extract_vector(url)
        self.assertEqual(len(vector), 22)
        self.assertEqual(len(vector), len(FeatureExtractor.FEATURE_NAMES))

    def test_ip_address_detection(self):
        """Should detect raw IPv4/IPv6 addresses correctly."""
        self.assertEqual(is_ip_address("192.168.1.1"), 1)
        self.assertEqual(is_ip_address("10.0.0.1"), 1)
        self.assertEqual(is_ip_address("google.com"), 0)
        self.assertEqual(is_ip_address("paypal-secure.com"), 0)

    def test_subdomain_count(self):
        """Should calculate subdomain count."""
        self.assertEqual(count_subdomains("google.com"), 0)
        self.assertEqual(count_subdomains("mail.google.com"), 1)
        self.assertEqual(count_subdomains("secure.login.paypal.attacker.com"), 3)

    def test_shannon_entropy(self):
        """Shannon entropy should be greater for randomized strings."""
        low_entropy = calculate_shannon_entropy("aaaaaaaa")
        high_entropy = calculate_shannon_entropy("a98df7b03bca01")
        self.assertGreater(high_entropy, low_entropy)

    def test_shortener_detection(self):
        """Should flag known URL shorteners."""
        feats = FeatureExtractor.extract_features("http://bit.ly/3xY71k")
        self.assertEqual(feats["is_shortened"], 1)

        normal_feats = FeatureExtractor.extract_features("https://github.com/torvalds")
        self.assertEqual(normal_feats["is_shortened"], 0)

    def test_suspicious_keywords(self):
        """Should count credential harvesting keywords."""
        url = "http://fakebank.com/secure/login/verify-account"
        feats = FeatureExtractor.extract_features(url)
        self.assertGreaterEqual(feats["suspicious_keyword_count"], 3)


if __name__ == "__main__":
    unittest.main()
