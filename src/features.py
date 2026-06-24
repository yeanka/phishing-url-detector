"""
PhishGuard — URL Feature Extractor
====================================
Extracts security-relevant numerical and boolean features from raw URLs.
These features are fed into the ML classifier alongside TF-IDF vectors.

Features extracted:
  - Structural: length, dots, slashes, special chars, digits
  - Security signals: HTTPS, IP address, @ symbol, port number
  - Complexity: Shannon entropy, subdomain depth
  - Heuristics: brand keywords, suspicious TLDs, path depth
"""

import re
import math
import urllib.parse
from typing import Dict, List

# Known legitimate TLDs vs suspicious ones
SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
                   ".top", ".club", ".online", ".site", ".info", ".biz"}

BRAND_KEYWORDS = {
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "instagram", "linkedin", "ebay", "bank", "chase",
    "wellsfargo", "citibank", "irs", "fedex", "dhl", "usps",
    "login", "verify", "secure", "update", "account", "confirm",
    "suspended", "alert", "authenticate", "validate", "billing",
}


def shannon_entropy(s: str) -> float:
    """
    Shannon entropy measures the randomness/unpredictability of a string.
    Higher entropy = more random-looking = more suspicious.

    Formula: H = -Σ p(x) * log2(p(x))
    """
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def has_ip_address(url: str) -> bool:
    """Returns True if the URL uses an IP address instead of a domain name."""
    ip_pattern = re.compile(
        r'(https?://)?(\d{1,3}\.){3}\d{1,3}'
    )
    return bool(ip_pattern.search(url))


def get_subdomain_depth(hostname: str) -> int:
    """Counts the number of subdomains (dots minus 1 for domain.tld)."""
    parts = hostname.split(".")
    return max(0, len(parts) - 2)


def count_brand_keywords(url: str) -> int:
    """Counts how many brand/phishing-related keywords appear in the URL."""
    url_lower = url.lower()
    return sum(1 for kw in BRAND_KEYWORDS if kw in url_lower)


def has_suspicious_tld(url: str) -> bool:
    """Returns True if the URL uses a TLD commonly associated with phishing."""
    for tld in SUSPICIOUS_TLDS:
        if tld in url.lower():
            return True
    return False


def extract_features(url: str) -> Dict[str, float]:
    """
    Main feature extraction function.
    Takes a raw URL string and returns a dict of numerical features.

    Args:
        url: Raw URL string (e.g., "https://paypal-login.evil.xyz/verify")

    Returns:
        Dictionary of feature_name → float value
    """
    # Parse URL components
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc or ""
        path     = parsed.path or ""
        query    = parsed.query or ""
    except Exception:
        parsed   = None
        hostname = ""
        path     = ""
        query    = ""

    full = url.lower()

    features = {
        # ── Length features ──────────────────────────────────────
        "url_length":          len(url),
        "hostname_length":     len(hostname),
        "path_length":         len(path),
        "query_length":        len(query),

        # ── Count features ───────────────────────────────────────
        "count_dots":          url.count("."),
        "count_hyphens":       url.count("-"),
        "count_underscores":   url.count("_"),
        "count_slashes":       url.count("/"),
        "count_at":            url.count("@"),
        "count_ampersand":     url.count("&"),
        "count_equals":        url.count("="),
        "count_percent":       url.count("%"),
        "count_question":      url.count("?"),
        "count_digits":        sum(c.isdigit() for c in url),
        "count_special_chars": sum(not c.isalnum() for c in url),

        # ── Boolean flags (0 or 1) ───────────────────────────────
        "has_https":           int(url.startswith("https")),
        "has_ip_address":      int(has_ip_address(url)),
        "has_at_symbol":       int("@" in url),
        "has_port":            int(bool(re.search(r":\d{2,5}", hostname))),
        "has_double_slash":    int("//" in path),
        "has_hex_encoding":    int(bool(re.search(r"%[0-9a-fA-F]{2}", url))),
        "has_suspicious_tld":  int(has_suspicious_tld(url)),

        # ── Structural features ──────────────────────────────────
        "subdomain_depth":     get_subdomain_depth(hostname),
        "path_depth":          path.count("/"),
        "brand_keyword_count": count_brand_keywords(url),

        # ── Entropy (randomness) ─────────────────────────────────
        "url_entropy":         shannon_entropy(url),
        "hostname_entropy":    shannon_entropy(hostname),
        "path_entropy":        shannon_entropy(path),

        # ── Ratio features ───────────────────────────────────────
        "digit_ratio":         sum(c.isdigit() for c in url) / max(len(url), 1),
        "letter_ratio":        sum(c.isalpha() for c in url) / max(len(url), 1),
    }

    return features


def extract_features_batch(urls: List[str]) -> List[Dict[str, float]]:
    """Extract features from a list of URLs."""
    return [extract_features(url) for url in urls]


def get_feature_names() -> List[str]:
    """Returns the list of feature names (column order for the feature matrix)."""
    sample = extract_features("https://example.com/path")
    return list(sample.keys())


# ── Quick demo ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=python",
        "http://paypal-login-verify.secure-account.xyz/confirm.php",
        "http://192.168.1.1/admin/login",
        "https://amazon.com/dp/B08N5WRWNW",
        "http://amazon-account-suspended.free-login.tk/update?token=abc123xyz",
    ]

    print("="*70)
    print("PhishGuard — Feature Extraction Demo")
    print("="*70)

    for url in test_urls:
        feats = extract_features(url)
        label = "⚠️  SUSPICIOUS" if (
            feats["has_ip_address"] or
            feats["has_suspicious_tld"] or
            feats["brand_keyword_count"] > 2 or
            feats["url_length"] > 80
        ) else "✅ LOOKS OK"

        print(f"\n{label}")
        print(f"  URL       : {url[:70]}...")
        print(f"  Length    : {feats['url_length']}")
        print(f"  Entropy   : {feats['url_entropy']:.2f}")
        print(f"  Subdomains: {feats['subdomain_depth']}")
        print(f"  Brands kw : {feats['brand_keyword_count']}")
        print(f"  Has HTTPS : {bool(feats['has_https'])}")
        print(f"  Has IP    : {bool(feats['has_ip_address'])}")
        print(f"  Bad TLD   : {bool(feats['has_suspicious_tld'])}")
