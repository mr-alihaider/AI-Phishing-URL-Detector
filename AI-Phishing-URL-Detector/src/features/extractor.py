"""
Feature Extraction Module for AI-Powered Phishing URL Detection System.

Extracts lexical, structural, statistical, and security heuristic features
from raw URLs to distinguish malicious phishing sites from legitimate domains.
"""

import math
import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Any


# Common URL Shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "bl.ink", "tiny.cc", "trib.al", "s.id", "rotf.lol",
    "shorturl.at", "rb.gy", "qr.ae"
}

# High-risk TLDs commonly abused by automated phishing campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".work", ".click", ".loan", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".buzz", ".fit", ".surf", ".rest", ".monster", ".bar",
    ".cam", ".icu", ".cc", ".link"
}

# Credential-harvesting and urgency keywords
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "security", "account",
    "banking", "secure", "update", "confirm", "wallet", "recover",
    "password", "auth", "support", "credential", "suspend", "billing",
    "webscr", "ebayisapi", "cmd=_login"
]


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculates Shannon Entropy of a string to detect algorithmic
    randomness (e.g., DGA domain generation algorithms).
    """
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        prob = count / text_len
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def is_ip_address(hostname: str) -> int:
    """
    Returns 1 if the hostname is a direct IPv4 or IPv6 address.
    """
    if not hostname:
        return 0
    clean_host = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return 1
    except ValueError:
        return 0


def count_subdomains(hostname: str) -> int:
    """
    Estimates the number of subdomains in the hostname.
    Example: 'pay.paypal.com' -> 1 subdomain ('pay')
             'evil.paypal.com.attacker.com' -> 3 subdomains
    """
    if not hostname or is_ip_address(hostname):
        return 0
    parts = hostname.strip(".").split(".")
    if len(parts) <= 2:
        return 0
    return max(0, len(parts) - 2)


def get_longest_consecutive_char(text: str) -> int:
    """
    Returns the length of the longest contiguous sequence of the same character.
    """
    if not text:
        return 0
    max_len = 1
    cur_len = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            cur_len += 1
            if cur_len > max_len:
                max_len = cur_len
        else:
            cur_len = 1
    return max_len


class FeatureExtractor:
    """
    Extracts 22 feature attributes from a URL string for machine learning.
    """

    FEATURE_NAMES = [
        "url_length",
        "hostname_length",
        "path_length",
        "count_dots",
        "count_hyphens",
        "count_at",
        "count_question",
        "count_equal",
        "count_slash",
        "count_percent",
        "count_subdomains",
        "has_ip_address",
        "is_https",
        "has_https_in_hostname",
        "is_shortened",
        "digit_ratio",
        "letter_ratio",
        "shannon_entropy",
        "suspicious_keyword_count",
        "suspicious_tld",
        "has_punycode",
        "consecutive_chars_max"
    ]

    @classmethod
    def normalize_url(cls, raw_url: str) -> str:
        """
        Normalizes URL by stripping whitespace and ensuring scheme exists.
        """
        raw_url = raw_url.strip()
        if not re.match(r"^https?://", raw_url, re.IGNORECASE):
            raw_url = "http://" + raw_url
        return raw_url

    @classmethod
    def extract_features(cls, url: str) -> Dict[str, Any]:
        """
        Extracts feature dictionary from the given URL.
        """
        norm_url = cls.normalize_url(url)
        parsed = urlparse(norm_url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        url_lower = norm_url.lower()

        # Length features
        url_len = len(norm_url)
        host_len = len(hostname)
        path_len = len(path)

        # Character counts
        count_dots = norm_url.count(".")
        count_hyphens = norm_url.count("-")
        count_at = norm_url.count("@")
        count_question = norm_url.count("?")
        count_equal = norm_url.count("=")
        count_slash = norm_url.count("/")
        count_percent = norm_url.count("%")

        # Structural & heuristic features
        subdomain_cnt = count_subdomains(hostname)
        has_ip = is_ip_address(hostname)
        is_https = 1 if parsed.scheme.lower() == "https" else 0
        has_https_in_host = 1 if ("https" in hostname or "http" in hostname.split(".")[0]) else 0
        is_shortened = 1 if hostname in SHORTENER_DOMAINS else 0

        # Statistical ratios
        digits = sum(c.isdigit() for c in norm_url)
        letters = sum(c.isalpha() for c in norm_url)
        digit_ratio = round(digits / url_len, 4) if url_len > 0 else 0.0
        letter_ratio = round(letters / url_len, 4) if url_len > 0 else 0.0
        entropy = calculate_shannon_entropy(norm_url)

        # Keyword matching
        keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

        # Suspicious TLD check
        has_suspicious_tld = 1 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

        # Punycode / Homograph attack check
        has_punycode = 1 if "xn--" in hostname else 0

        # Consecutive repeated characters
        consecutive_max = get_longest_consecutive_char(hostname)

        return {
            "url_length": url_len,
            "hostname_length": host_len,
            "path_length": path_len,
            "count_dots": count_dots,
            "count_hyphens": count_hyphens,
            "count_at": count_at,
            "count_question": count_question,
            "count_equal": count_equal,
            "count_slash": count_slash,
            "count_percent": count_percent,
            "count_subdomains": subdomain_cnt,
            "has_ip_address": has_ip,
            "is_https": is_https,
            "has_https_in_hostname": has_https_in_host,
            "is_shortened": is_shortened,
            "digit_ratio": digit_ratio,
            "letter_ratio": letter_ratio,
            "shannon_entropy": entropy,
            "suspicious_keyword_count": keyword_hits,
            "suspicious_tld": has_suspicious_tld,
            "has_punycode": has_punycode,
            "consecutive_chars_max": consecutive_max
        }

    @classmethod
    def extract_vector(cls, url: str) -> List[float]:
        """
        Extracts features as a fixed-order numeric list for machine learning models.
        """
        feat_dict = cls.extract_features(url)
        return [float(feat_dict[name]) for name in cls.FEATURE_NAMES]
