"""
PhishGuard — URL Prediction (Inference)
========================================
Loads the trained model and classifies new URLs as phishing or legitimate.
Provides a confidence score and an explanation of contributing features.

Usage:
    # Single URL
    python src/predict.py --url "http://paypal-login.verify-now.xyz/account"

    # Batch from file (one URL per line)
    python src/predict.py --file urls_to_check.txt

    # Interactive mode
    python src/predict.py --interactive
"""

import os
import sys
import pickle
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.features import extract_features

MODEL_PATH = "models/phishguard_model.pkl"


# ── Colour helpers ─────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    ORANGE = "\033[93m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def load_model(path=MODEL_PATH):
    if not os.path.exists(path):
        print(f"{C.RED}[!] Model not found: {path}{C.RESET}")
        print(f"    Run first: python src/train.py")
        sys.exit(1)
    with open(path, "rb") as f:
        return pickle.load(f)


def explain_prediction(url: str, features: dict) -> list:
    """
    Returns a list of human-readable reasons why a URL looks suspicious or safe.
    Beginner-friendly explanation layer.
    """
    reasons = []

    if features["has_ip_address"]:
        reasons.append("⚠️  Uses IP address instead of domain name")
    if features["has_suspicious_tld"]:
        reasons.append("⚠️  Uses a suspicious top-level domain (.xyz, .tk, etc.)")
    if features["brand_keyword_count"] >= 2:
        reasons.append(f"⚠️  Contains {int(features['brand_keyword_count'])} brand/phishing keywords (e.g. 'paypal', 'verify')")
    if features["url_length"] > 75:
        reasons.append(f"⚠️  Unusually long URL ({int(features['url_length'])} characters)")
    if features["count_hyphens"] >= 3:
        reasons.append(f"⚠️  Many hyphens ({int(features['count_hyphens'])}) — common in fake domains")
    if features["subdomain_depth"] >= 3:
        reasons.append(f"⚠️  Deep subdomain structure ({int(features['subdomain_depth'])} levels)")
    if features["url_entropy"] > 4.2:
        reasons.append(f"⚠️  High URL entropy ({features['url_entropy']:.2f}) — looks randomly generated")
    if features["has_at_symbol"]:
        reasons.append("⚠️  Contains '@' symbol — used to disguise destination domain")
    if not features["has_https"]:
        reasons.append("⚠️  No HTTPS — connection is not encrypted")
    if features["count_percent"] >= 3:
        reasons.append(f"⚠️  URL encoding detected ({int(features['count_percent'])} '%' chars) — possible obfuscation")

    if not reasons:
        if features["has_https"]:
            reasons.append("✅ Uses HTTPS")
        if features["subdomain_depth"] <= 1:
            reasons.append("✅ Simple domain structure")
        if features["url_length"] < 50:
            reasons.append("✅ Normal URL length")
        reasons.append("✅ No known phishing patterns detected")

    return reasons


def predict_url(model, url: str, verbose=True) -> dict:
    """
    Run prediction on a single URL.

    Returns:
        dict with keys: url, prediction, label, confidence, features, reasons
    """
    features   = extract_features(url)
    label_int  = model.predict([url])[0]
    proba      = model.predict_proba([url])[0]
    confidence = proba[label_int] * 100
    label_str  = "PHISHING" if label_int == 1 else "LEGITIMATE"
    reasons    = explain_prediction(url, features)

    result = {
        "url":        url,
        "prediction": label_str,
        "label":      label_int,
        "confidence": round(confidence, 2),
        "phish_prob": round(proba[1] * 100, 2),
        "legit_prob": round(proba[0] * 100, 2),
        "features":   features,
        "reasons":    reasons,
    }

    if verbose:
        _print_result(result)

    return result


def _print_result(result: dict):
    """Pretty-print a single prediction result."""
    is_phishing = result["label"] == 1
    color       = C.RED if is_phishing else C.GREEN
    icon        = "🎣" if is_phishing else "✅"

    print(f"\n{'─'*60}")
    print(f"  URL: {result['url'][:70]}{'...' if len(result['url']) > 70 else ''}")
    print(f"{'─'*60}")
    print(f"  {icon} Verdict    : {color}{C.BOLD}{result['prediction']}{C.RESET}")
    print(f"  📊 Confidence : {result['confidence']:.1f}%")
    print(f"  🟢 Legit prob : {result['legit_prob']:.1f}%")
    print(f"  🔴 Phish prob : {result['phish_prob']:.1f}%")
    print(f"\n  Key signals:")
    for reason in result["reasons"]:
        print(f"    {reason}")
    print(f"{'─'*60}")


def predict_batch(model, filepath: str):
    """Predict all URLs in a text file (one per line)."""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with open(filepath) as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"\n[*] Scanning {len(urls)} URLs from {filepath}...\n")

    phishing_count = 0
    for url in urls:
        result = predict_url(model, url, verbose=True)
        if result["label"] == 1:
            phishing_count += 1

    print(f"\n{'='*60}")
    print(f"  Batch Scan Complete")
    print(f"  Total URLs   : {len(urls)}")
    print(f"  Phishing     : {phishing_count} ({phishing_count/len(urls)*100:.1f}%)")
    print(f"  Legitimate   : {len(urls) - phishing_count}")
    print(f"{'='*60}\n")


def interactive_mode(model):
    """Run an interactive CLI prompt for testing URLs."""
    print(f"\n{C.BOLD}PhishGuard — Interactive Mode{C.RESET}")
    print("Type a URL to analyse. Enter 'quit' to exit.\n")

    while True:
        try:
            url = input(f"{C.BLUE}Enter URL:{C.RESET} ").strip()
            if url.lower() in ("quit", "exit", "q"):
                print("Goodbye!")
                break
            if not url:
                continue
            # Add scheme if missing
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            predict_url(model, url)
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard — Phishing URL Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/predict.py --url "http://paypal-verify.xyz/login"
  python src/predict.py --file urls.txt
  python src/predict.py --interactive
        """
    )
    parser.add_argument("--url",         help="Single URL to classify")
    parser.add_argument("--file",        help="Text file with one URL per line")
    parser.add_argument("--interactive", action="store_true", help="Interactive prompt mode")
    parser.add_argument("--model",       default=MODEL_PATH, help="Path to trained model .pkl")
    args = parser.parse_args()

    print(f"[*] Loading model: {args.model}")
    model = load_model(args.model)
    print(f"[+] Model ready\n")

    if args.url:
        predict_url(model, args.url)
    elif args.file:
        predict_batch(model, args.file)
    elif args.interactive:
        interactive_mode(model)
    else:
        # Default demo if no args given
        demo_urls = [
            "https://www.google.com/search?q=machine+learning",
            "http://paypal-account-suspended.verify-now.xyz/login.php",
            "https://github.com/topics/cybersecurity",
            "http://192.168.10.44/phish/steal_credentials",
            "https://amazon.com/dp/B08N5WRWNW",
            "http://amazon-billing-update.free-gifts.tk/confirm?token=xYz19283",
        ]
        print("[*] Running demo predictions...\n")
        for url in demo_urls:
            predict_url(model, url)


if __name__ == "__main__":
    main()
