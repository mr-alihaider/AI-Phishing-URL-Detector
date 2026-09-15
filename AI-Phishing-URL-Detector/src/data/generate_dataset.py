"""
Dataset Generator & Preprocessor for Phishing URL Detection.

Generates a realistic, diverse dataset containing legitimate URLs
(e-commerce, search, education, news, government, open-source)
and sophisticated phishing URLs (typosquatting, IP-based, multi-subdomain spoofing,
credential harvesters, DGA-like random hosts, homographs).
"""

import os
import sys
import csv
import random
from typing import List, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.features.extractor import FeatureExtractor

LEGITIMATE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com",
    "amazon.com", "twitter.com", "instagram.com", "linkedin.com", "reddit.com",
    "netflix.com", "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "cnn.com", "bbc.com", "nytimes.com", "theguardian.com", "forbes.com",
    "harvard.edu", "mit.edu", "stanford.edu", "ox.ac.uk", "cam.ac.uk",
    "gov.uk", "usa.gov", "nih.gov", "nasa.gov", "who.int",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com", "paypal.com",
    "dropbox.com", "slack.com", "zoom.us", "spotify.com", "twitch.tv",
    "ebay.com", "walmart.com", "target.com", "aliexpress.com", "etsy.com",
    "cloudflare.com", "aws.amazon.com", "azure.microsoft.com", "digitalocean.com", "docker.com",
    "medium.com", "quora.com", "pinterest.com", "tumblr.com", "imdb.com",
    "mozilla.org", "python.org", "apache.org", "ubuntu.com", "debian.org"
]

LEGIT_PATHS = [
    "", "/", "/about", "/contact", "/terms", "/privacy", "/blog", "/news/2026/05/update",
    "/docs/api/v2/reference", "/user/profile/settings", "/products/category/electronics",
    "/search?q=machine+learning+tutorial", "/watch?v=dQw4w9WgXcQ", "/wiki/Cybersecurity",
    "/features/overview", "/pricing/enterprise", "/community/discussions/topic-491",
    "/download/latest/release.zip", "/faq/billing-and-subscriptions", "/help/article/90412"
]

TARGET_BRANDS = [
    "paypal", "chase", "bankofamerica", "wellsfargo", "apple", "microsoft", "google",
    "netflix", "amazon", "facebook", "instagram", "coinbase", "binance", "metamask",
    "dropbox", "dhl", "fedex", "usps", "whatsapp", "telegram"
]

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update", "account", "suspended", "confirm",
    "wallet-auth", "recover-access", "security-alert", "billing-update", "validation"
]

MALICIOUS_TLDS = [
    ".xyz", ".top", ".work", ".click", ".loan", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".buzz", ".cam", ".icu", ".cc", ".link", ".info"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "shorturl.at", "cutt.ly"
]


def generate_legitimate_urls(count: int = 3000) -> List[Tuple[str, int]]:
    """Generates legitimate benign URL samples."""
    samples = []
    random.seed(42)
    for _ in range(count):
        domain = random.choice(LEGITIMATE_DOMAINS)
        sub = ""
        if random.random() < 0.25:
            sub = random.choice(["blog", "docs", "app", "help", "support", "api", "shop"]) + "."
        path = random.choice(LEGIT_PATHS)
        if random.random() < 0.3:
            path += f"?id={random.randint(100, 99999)}&ref={random.choice(['home', 'nav', 'footer', 'email'])}"
        proto = "https://" if random.random() < 0.95 else "http://"
        url = f"{proto}{sub}{domain}{path}"
        samples.append((url, 0))
    return samples


def generate_phishing_urls(count: int = 3000) -> List[Tuple[str, int]]:
    """Generates varied realistic phishing URL samples with malicious heuristics."""
    samples = []
    random.seed(1337)
    
    for _ in range(count):
        attack_type = random.choice([
            "subdomain_spoof", "typosquatting", "ip_address", "tld_abuse",
            "credential_path", "shortener_abuse", "dga_random", "punycode"
        ])
        brand = random.choice(TARGET_BRANDS)
        action = random.choice(SUSPICIOUS_WORDS)

        if attack_type == "subdomain_spoof":
            # e.g., paypal.com-security-check.attackerdomain.xyz/login
            attacker_tld = random.choice(MALICIOUS_TLDS)
            url = f"http://{brand}.com-{action}-verify.attacker-servers{attacker_tld}/{action}.php?auth_token={random.randint(10000, 99999)}"

        elif attack_type == "typosquatting":
            # replace letters: o->0, l->1, e->3
            typo_brand = brand.replace("o", "0").replace("l", "1").replace("e", "3")
            if typo_brand == brand:
                typo_brand = brand + "-secure"
            tld = random.choice([".com", ".net", ".org", ".co"])
            url = f"http://www.{typo_brand}{tld}/webscr/{action}?cmd=_login_submit"

        elif attack_type == "ip_address":
            # e.g., http://192.168.1.1/paypal/signin
            ip = f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            url = f"http://{ip}/{brand}/{action}-account/index.php"

        elif attack_type == "tld_abuse":
            tld = random.choice(MALICIOUS_TLDS)
            url = f"http://{brand}-{action}{tld}/signin-confirmation"

        elif attack_type == "credential_path":
            # Deep path with multiple keywords and params
            tld = random.choice([".net", ".xyz", ".top", ".biz"])
            url = f"http://customer-support-{brand}{tld}/secure/banking/verify?user_id={random.randint(1000, 9999)}&action=unlock"

        elif attack_type == "shortener_abuse":
            shortener = random.choice(SHORTENERS)
            rand_code = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=7))
            url = f"http://{shortener}/{rand_code}"

        elif attack_type == "dga_random":
            # High entropy random string domain
            random_host = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
            tld = random.choice(MALICIOUS_TLDS)
            url = f"http://{random_host}{tld}/{brand}-{action}/"

        elif attack_type == "punycode":
            # Homograph simulation
            url = f"http://xn--{brand}66a.com/account/{action}"

        samples.append((url, 1))
    return samples


def create_dataset_file(filepath: str, total_samples: int = 6000) -> str:
    """Creates and saves labeled dataset to CSV."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    half = total_samples // 2
    benign = generate_legitimate_urls(half)
    phishing = generate_phishing_urls(half)
    combined = benign + phishing
    random.seed(999)
    random.shuffle(combined)

    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url, label in combined:
            writer.writerow([url, label])

    print(f"[+] Dataset successfully created with {len(combined)} samples at: {filepath}")
    return filepath


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_csv = os.path.join(current_dir, "dataset.csv")
    create_dataset_file(output_csv, total_samples=6000)
