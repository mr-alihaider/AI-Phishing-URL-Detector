"""
Inference & Risk Scoring Engine for Phishing URL Detection.

Provides single and batch prediction, Explainable AI (XAI) threat indicators,
and normalized risk scores (0-100%).
"""

import os
import sys
from typing import Dict, List, Any, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import joblib
import numpy as np

from src.features.extractor import FeatureExtractor, SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, SHORTENER_DOMAINS


DEFAULT_MODEL_PATH = os.path.join(PROJECT_ROOT, "saved_models", "phishing_detector.pkl")


class PhishingPredictor:
    """
    Production-ready classifier for analyzing URLs in real-time.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.model = None
        self._ensure_model_loaded()

    def _ensure_model_loaded(self):
        """Loads trained model or triggers training if not found."""
        if not os.path.exists(self.model_path):
            print(f"[*] Saved model not found at {self.model_path}. Training initial model...")
            from src.models.trainer import train_and_evaluate
            train_and_evaluate(output_model_path=self.model_path)

        self.model = joblib.load(self.model_path)

    @staticmethod
    def _generate_threat_indicators(url: str, features: Dict[str, Any]) -> List[str]:
        """
        Translates raw numerical features into human-readable cybersecurity explanations.
        """
        indicators = []
        url_lower = url.lower()

        if features.get("has_ip_address", 0) == 1:
            indicators.append("Direct IP address used as hostname instead of a registered domain.")

        if features.get("is_shortened", 0) == 1:
            indicators.append("Known URL shortener domain detected (hides destination target).")

        if features.get("suspicious_tld", 0) == 1:
            indicators.append("Top-Level Domain (TLD) matches high-abuse phishing registry.")

        if features.get("is_https", 1) == 0:
            indicators.append("Insecure HTTP protocol used (missing SSL/TLS encryption).")

        if features.get("has_https_in_hostname", 0) == 1:
            indicators.append("Deceptive 'https' token embedded directly inside domain name.")

        if features.get("count_subdomains", 0) >= 3:
            indicators.append(f"Excessive subdomain nesting ({features['count_subdomains']} subdomains) detected.")

        if features.get("suspicious_keyword_count", 0) > 0:
            found_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
            indicators.append(f"Contains credential/banking keywords: {found_kws[:4]}")

        if features.get("shannon_entropy", 0.0) > 4.25:
            indicators.append(f"Abnormally high entropy ({features['shannon_entropy']}) - likely machine-generated.")

        if features.get("url_length", 0) > 85:
            indicators.append(f"Abnormally long URL string ({features['url_length']} characters).")

        if features.get("count_at", 0) > 0:
            indicators.append("Contains '@' symbol (often used to obscure legitimate destination).")

        if features.get("has_punycode", 0) == 1:
            indicators.append("Punycode (xn--) detected - possible IDN homograph spoofing attack.")

        if not indicators and features.get("is_https", 1) == 1:
            indicators.append("Clean domain reputation pattern; verified HTTPS protocol.")

        return indicators

    def predict(self, raw_url: str) -> Dict[str, Any]:
        """
        Analyzes a single URL and returns rich detection diagnostics.
        """
        if not raw_url or not raw_url.strip():
            return {
                "error": "Empty or invalid URL provided",
                "is_phishing": False,
                "risk_score": 0
            }

        url = raw_url.strip()
        features = FeatureExtractor.extract_features(url)
        vector = np.array([FeatureExtractor.extract_vector(url)], dtype=np.float32)

        # Probabilities: [P(legitimate), P(phishing)]
        proba = self.model.predict_proba(vector)[0]
        phishing_prob = float(proba[1])
        risk_score = round(phishing_prob * 100, 1)

        is_phishing = bool(risk_score >= 50.0)
        label = "Phishing" if is_phishing else "Legitimate"

        # Severity categorization
        if risk_score < 30:
            risk_level = "Safe"
            status_color = "success"
        elif risk_score < 65:
            risk_level = "Suspicious"
            status_color = "warning"
        else:
            risk_level = "Critical Phishing"
            status_color = "danger"

        threat_indicators = self._generate_threat_indicators(url, features)

        return {
            "url": url,
            "label": label,
            "is_phishing": is_phishing,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confidence": round(float(np.max(proba)), 4),
            "status_color": status_color,
            "threat_indicators": threat_indicators,
            "features": features
        }

    def predict_batch(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Analyzes a batch of URLs.
        """
        return [self.predict(u) for u in urls if u and u.strip()]
