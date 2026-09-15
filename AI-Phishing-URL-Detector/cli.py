"""
Command Line Interface (CLI) for AI-Powered Phishing URL Detection System.

Usage:
    python cli.py --url "https://example.com"
    python cli.py --file urls.txt
    python cli.py --interactive
"""

import sys
import os
import argparse

# Fix Windows console UTF-8 output encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.models.predict import PhishingPredictor

# ANSI Color formatting
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    banner = f"""{CYAN}{BOLD}
+==============================================================+
|         [!] AI-POWERED PHISHING URL DETECTION SYSTEM         |
|       Deep Feature Extraction & Machine Learning Engine      |
+==============================================================+{RESET}"""
    print(banner)


def render_risk_meter(risk_score: float) -> str:
    """Renders a terminal progress meter for risk score."""
    total_bars = 20
    filled = int(round(total_bars * (risk_score / 100.0)))
    unfilled = total_bars - filled

    if risk_score < 35:
        color = GREEN
    elif risk_score < 70:
        color = YELLOW
    else:
        color = RED

    bar = f"{color}[{'#' * filled}{'.' * unfilled}] {risk_score:.1f}%{RESET}"
    return bar


def display_result(result: dict, verbose: bool = False):
    """Prints formatted detection diagnostics."""
    if "error" in result:
        print(f"{RED}[!] Error: {result['error']}{RESET}\n")
        return

    is_phish = result["is_phishing"]
    score = result["risk_score"]
    level = result["risk_level"]
    url = result["url"]

    status_tag = f"{RED}[DANGEROUS PHISHING]{RESET}" if is_phish else f"{GREEN}[LEGITIMATE / SAFE]{RESET}"
    
    print("\n" + "-" * 62)
    print(f"{BOLD}Target URL  :{RESET} {url}")
    print(f"{BOLD}Verdict     :{RESET} {status_tag} ({level})")
    print(f"{BOLD}Risk Gauge  :{RESET} {render_risk_meter(score)}")
    print(f"{BOLD}Confidence  :{RESET} {result['confidence'] * 100:.2f}%")
    print("-" * 62)

    print(f"{BOLD}Threat Indicators & Behavioral Signals:{RESET}")
    for ind in result["threat_indicators"]:
        bullet_color = RED if is_phish else GREEN
        print(f"  {bullet_color}[*]{RESET} {ind}")

    if verbose:
        print("\n" + f"{CYAN}--- Extracted Feature Telemetry ---{RESET}")
        feats = result.get("features", {})
        for k, v in feats.items():
            print(f"  {k.ljust(28)}: {v}")
    print("-" * 62 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="AI Phishing URL Detector CLI - Real-time heuristic & ML security scanner"
    )
    parser.add_argument("--url", "-u", type=str, help="Single target URL to analyze")
    parser.add_argument("--file", "-f", type=str, help="Text file containing list of URLs (one per line)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print full 22-feature vector telemetry")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive terminal scanner")

    args = parser.parse_args()
    print_banner()

    predictor = PhishingPredictor()

    if args.url:
        result = predictor.predict(args.url)
        display_result(result, verbose=args.verbose)

    elif args.file:
        if not os.path.exists(args.file):
            print(f"{RED}[!] File not found: {args.file}{RESET}")
            sys.exit(1)

        with open(args.file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]

        print(f"{CYAN}[*] Scanning batch of {len(urls)} URLs...{RESET}\n")
        phish_count = 0
        for u in urls:
            res = predictor.predict(u)
            if res["is_phishing"]:
                phish_count += 1
            display_result(res, verbose=args.verbose)

        print(f"{BOLD}=== Batch Scan Summary ==={RESET}")
        print(f"Total Scanned   : {len(urls)}")
        print(f"Flagged Phishing: {RED}{phish_count}{RESET}")
        print(f"Verified Safe   : {GREEN}{len(urls) - phish_count}{RESET}")

    elif args.interactive or len(sys.argv) == 1:
        print(f"{CYAN}Interactive Mode Activated. Type 'exit' or 'quit' to stop.{RESET}\n")
        while True:
            try:
                user_url = input(f"{BOLD}Enter URL to inspect > {RESET}").strip()
                if user_url.lower() in ("exit", "quit", "q"):
                    print("Exiting scanner. Stay safe!")
                    break
                if not user_url:
                    continue
                res = predictor.predict(user_url)
                display_result(res, verbose=args.verbose)
            except (KeyboardInterrupt, EOFError):
                print("\nSession ended.")
                break


if __name__ == "__main__":
    main()
