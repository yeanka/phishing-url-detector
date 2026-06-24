"""
PhishGuard — Synthetic Dataset Generator
=========================================
Generates a labelled CSV dataset of phishing and legitimate URLs
for training the PhishGuard ML classifier.

Each URL is labelled:
  0 = Legitimate
  1 = Phishing

Run:
    python data/generate_dataset.py
"""

import csv
import random
import string
import os

random.seed(42)

# ── Legitimate URL patterns ─────────────────────────────────────────────────

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "twitter.com",
    "instagram.com", "linkedin.com", "github.com", "stackoverflow.com", "reddit.com",
    "wikipedia.org", "bbc.com", "cnn.com", "microsoft.com", "apple.com",
    "netflix.com", "spotify.com", "dropbox.com", "slack.com", "zoom.us",
    "paypal.com", "ebay.com", "walmart.com", "target.com", "coursera.org",
    "udemy.com", "medium.com", "notion.so", "trello.com", "atlassian.com",
]

LEGIT_PATHS = [
    "/", "/home", "/about", "/contact", "/products", "/services",
    "/blog", "/news", "/help", "/support", "/login", "/signup",
    "/search?q=python", "/docs/api", "/pricing", "/features",
    "/account/settings", "/dashboard", "/explore", "/trending",
]

LEGIT_PROTOCOLS = ["https://", "https://www."]

def make_legit_url():
    protocol = random.choice(LEGIT_PROTOCOLS)
    domain   = random.choice(LEGIT_DOMAINS)
    path     = random.choice(LEGIT_PATHS)
    return f"{protocol}{domain}{path}"


# ── Phishing URL patterns ────────────────────────────────────────────────────

PHISHING_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "instagram", "linkedin", "ebay", "bank", "chase",
    "wellsfargo", "citibank", "irs", "fedex", "dhl", "usps",
]

PHISHING_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "confirm",
    "suspended", "alert", "urgent", "authenticate", "validate",
    "billing", "payment", "checkout", "signin", "portal",
]

PHISHING_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
    ".club", ".online", ".site", ".info", ".biz",
]

PHISHING_EVIL_DOMAINS = [
    "free-gift-claim", "secure-login-portal", "account-verify",
    "update-required", "urgent-action", "login-confirm",
    "security-alert", "account-suspended", "verify-identity",
]

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def make_phishing_url():
    style = random.randint(1, 6)

    if style == 1:
        # Brand impersonation with hyphen tricks
        brand   = random.choice(PHISHING_BRANDS)
        keyword = random.choice(PHISHING_KEYWORDS)
        tld     = random.choice(PHISHING_TLDS)
        evil    = random.choice(PHISHING_EVIL_DOMAINS)
        return f"http://{brand}-{keyword}.{evil}{tld}/{random_string(6)}.php"

    elif style == 2:
        # IP address instead of domain
        ip   = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
        path = random.choice(PHISHING_KEYWORDS)
        return f"http://{ip}/{path}/{random_string(4)}"

    elif style == 3:
        # Legitimate brand in subdomain
        brand   = random.choice(PHISHING_BRANDS)
        keyword = random.choice(PHISHING_KEYWORDS)
        evil    = random.choice(PHISHING_EVIL_DOMAINS)
        tld     = random.choice(PHISHING_TLDS)
        return f"http://{brand}.{evil}{tld}/{keyword}"

    elif style == 4:
        # Lookalike domain with extra characters
        brand   = random.choice(PHISHING_BRANDS)
        noise   = random_string(4)
        tld     = random.choice(PHISHING_TLDS)
        keyword = random.choice(PHISHING_KEYWORDS)
        return f"http://www.{brand}{noise}{tld}/{keyword}.html"

    elif style == 5:
        # @ trick (browser reads after @)
        brand    = random.choice(PHISHING_BRANDS)
        evil     = random.choice(PHISHING_EVIL_DOMAINS)
        tld      = random.choice(PHISHING_TLDS)
        return f"http://{brand}.com@{evil}{tld}/steal"

    else:
        # Very long obfuscated URL
        brand   = random.choice(PHISHING_BRANDS)
        keyword = random.choice(PHISHING_KEYWORDS)
        junk    = random_string(random.randint(20, 40))
        tld     = random.choice(PHISHING_TLDS)
        return f"http://{brand}-{keyword}-{junk}{tld}/redirect?token={random_string(16)}&ref={random_string(8)}"


# ── Generate & Save ──────────────────────────────────────────────────────────

def generate_dataset(n_legit=500, n_phishing=500, output_path="data/urls_dataset.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    rows = []

    for _ in range(n_legit):
        rows.append({"url": make_legit_url(), "label": 0, "type": "legitimate"})

    for _ in range(n_phishing):
        rows.append({"url": make_phishing_url(), "label": 1, "type": "phishing"})

    random.shuffle(rows)

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label", "type"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"✅ Dataset saved → {output_path}")
    print(f"   Total URLs  : {len(rows)}")
    print(f"   Legitimate  : {n_legit}")
    print(f"   Phishing    : {n_phishing}")

    # Print 5 examples of each
    print("\n--- Sample Legitimate URLs ---")
    legit = [r["url"] for r in rows if r["label"] == 0][:5]
    for u in legit:
        print(f"  ✅ {u}")

    print("\n--- Sample Phishing URLs ---")
    phish = [r["url"] for r in rows if r["label"] == 1][:5]
    for u in phish:
        print(f"  ⚠️  {u}")


if __name__ == "__main__":
    generate_dataset(n_legit=500, n_phishing=500)
