"""
PhishGuard AI — Enhanced Deterministic URL Analysis Engine
Extends the existing rule_engine.analyze_url with richer flags.

Checks:
  - IP-based URLs
  - Shortened URLs
  - Suspicious TLDs
  - Punycode / IDN look-alike domains
  - Look-alike/typosquatting domain names
  - Suspicious subdomains (excessive depth, keyword injection)
  - Suspicious URL paths (long random strings, encoded payloads)
  - HTTP vs HTTPS
  - Trusted-domain membership (supporting evidence only)
  - Payment / banking keyword in path
"""

import re
from typing import Dict, List
from urllib.parse import urlparse, unquote

# ── Trusted domain list (local, static) ─────────────────────────────────────────
# Presence → supporting evidence of legitimacy (NOT conclusive).
# Absence  → no impact on score on its own.
TRUSTED_DOMAINS = {
    # Banks – India
    "hdfcbank.com", "onlinesbi.sbi", "sbi.co.in", "icicibank.com",
    "axisbank.com", "kotakbank.com", "yesbank.in", "pnbindia.in",
    "canarabank.com", "unionbankofindia.co.in", "bankofbaroda.in",
    # Payments
    "paytm.com", "phonepe.com", "gpay.app", "bhimupi.org.in",
    "razorpay.com", "amazon.in", "amazon.com",
    # E-commerce
    "flipkart.com", "myntra.com", "meesho.com", "swiggy.com", "zomato.com",
    # Govt / Regulatory
    "rbi.org.in", "uidai.gov.in", "incometax.gov.in", "gstn.gov.in",
    "trai.gov.in", "india.gov.in", "digitalindia.gov.in",
    # Telecom
    "airtel.in", "jio.com", "bsnl.co.in", "myvi.in",
    # Logistics
    "delhivery.com", "bluedart.com", "dtdc.com", "indiapost.gov.in",
    "fedex.com", "dhl.com",
    # International
    "paypal.com", "microsoft.com", "apple.com", "google.com",
    "netflix.com", "spotify.com",
}

# ── Patterns ─────────────────────────────────────────────────────────────────────
_IP_URL_RE      = re.compile(r'https?://\d{1,3}(?:\.\d{1,3}){3}')
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "short.io", "rebrand.ly", "tiny.cc", "is.gd",
    "cutt.ly", "shorturl.at", "rb.gy", "clck.ru", "qps.ru",
    "su.pr", "soo.gd", "mcaf.ee", "url.ie", "v.gd",
}
_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".site", ".online", ".club", ".info",
    ".biz", ".link", ".pw", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".work", ".click", ".download", ".review", ".vip", ".monster",
    ".icu", ".cam", ".surf",
}
_LOOKALIKE_MAP = {
    "paypa1": "paypal", "pay-pal": "paypal", "paypall": "paypal",
    "micros0ft": "microsoft", "microsofl": "microsoft", "micro-soft": "microsoft",
    "g00gle": "google", "go0gle": "google", "googlee": "google",
    "amaz0n": "amazon", "amazzon": "amazon", "amzon": "amazon",
    "app1e": "apple", "aplee": "apple",
    "faceb00k": "facebook", "facebok": "facebook",
    "hdfc-": "hdfcbank", "hdfcb": "hdfcbank",
    "sbi-": "sbi", "sbionline": "sbi",
    "icici-": "icicibank",
    "netf1ix": "netflix", "netflx": "netflix",
}
_BANKING_PATH_KEYWORDS = re.compile(
    r'(login|signin|verify|kyc|update|secure|account|otp|auth|'
    r'authenticate|confirm|netbank|banking|payment|wallet|reward)',
    re.IGNORECASE
)
_ENCODED_PAYLOAD_RE = re.compile(r'%[0-9a-fA-F]{2}')
_LONG_RANDOM_RE     = re.compile(r'[a-zA-Z0-9]{25,}')


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        return parsed.hostname or ""
    except Exception:
        return url.lower()


def _is_punycode(domain: str) -> bool:
    return "xn--" in domain.lower()


def analyze_url_extended(url: str) -> Dict:
    """
    Extended deterministic URL analysis.
    Returns structured findings — never hallucinates.
    """
    flags: List[str] = []
    trust_notes: List[str] = []
    risk_score = 0  # 0–10 internal heuristic (not exposed as a standalone metric)

    url_clean = url.strip()
    domain = _extract_domain(url_clean)
    domain_lower = domain.lower()

    # ── 1. IP-based URL ──────────────────────────────────────────────────────────
    if _IP_URL_RE.match(url_clean):
        flags.append("IP-based URL (no domain name)")
        risk_score += 3

    # ── 2. HTTPS check ───────────────────────────────────────────────────────────
    if url_clean.startswith("http://"):
        flags.append("Non-HTTPS (unencrypted) URL")
        risk_score += 1

    # ── 3. Shortened URL ─────────────────────────────────────────────────────────
    for shortener in _SHORTENERS:
        if domain_lower == shortener or domain_lower.endswith(f".{shortener}"):
            flags.append(f"Shortened / redirect URL ({shortener})")
            risk_score += 2
            break

    # ── 4. Suspicious TLD ────────────────────────────────────────────────────────
    for tld in _SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            flags.append(f"Suspicious TLD ({tld})")
            risk_score += 2
            break

    # ── 5. Punycode / IDN ────────────────────────────────────────────────────────
    if _is_punycode(domain_lower):
        flags.append("Internationalized / punycode domain (possible look-alike)")
        risk_score += 2

    # ── 6. Look-alike / typosquatting ────────────────────────────────────────────
    parts = domain_lower.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain_lower
    for fake, real in _LOOKALIKE_MAP.items():
        if fake in domain_lower:
            if base_domain in TRUSTED_DOMAINS or (real in domain_lower and fake in real):
                continue
            flags.append(f"Possible typosquatting: '{domain}' resembles '{real}'")
            risk_score += 3
            break

    # ── 7. Subdomain depth / keyword injection ───────────────────────────────────
    if len(parts) > 4:
        flags.append("Excessive subdomain depth (≥5 labels)")
        risk_score += 1
    # Legitimate brand name used as a subdomain of an unknown domain
    if len(parts) >= 3:
        subdomain_part = ".".join(parts[:-2])
        known_brands = {"hdfc", "sbi", "icici", "paypal", "amazon", "microsoft",
                        "apple", "google", "netflix", "airtel", "jio"}
        for brand in known_brands:
            if brand in subdomain_part and brand not in ".".join(parts[-2:]):
                flags.append(
                    f"Brand '{brand}' appears as subdomain of unrelated domain"
                )
                risk_score += 2
                break

    # ── 8. URL path analysis ─────────────────────────────────────────────────────
    try:
        path = urlparse(url_clean).path + "?" + (urlparse(url_clean).query or "")
    except Exception:
        path = ""

    if _LONG_RANDOM_RE.search(path):
        flags.append("Long random-looking path string")
        risk_score += 1

    if len(path) > 200:
        flags.append("Unusually long URL path")
        risk_score += 1

    encoded_count = len(_ENCODED_PAYLOAD_RE.findall(path))
    if encoded_count > 5:
        flags.append(f"Heavily URL-encoded path ({encoded_count} encoded chars)")
        risk_score += 1

    # Banking keywords in path of non-trusted domain
    if _BANKING_PATH_KEYWORDS.search(path):
        # Only flag if domain is NOT in trusted list
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain_lower
        if base_domain not in TRUSTED_DOMAINS:
            flags.append("Banking/security keywords in URL path on untrusted domain")
            risk_score += 2

    # ── 9. Trusted-domain lookup (supporting evidence only) ──────────────────────
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain_lower
    if base_domain in TRUSTED_DOMAINS:
        trust_notes.append(
            f"Domain '{base_domain}' is in the local trusted-domain list "
            f"(supporting evidence only — spoofing is possible)"
        )
        # Being in trusted list does NOT cancel other flags
    else:
        trust_notes.append(
            f"Domain '{base_domain}' is not in the local trusted-domain list"
        )

    is_suspicious = len(flags) > 0

    return {
        "url":          url_clean,
        "domain":       domain_lower,
        "is_suspicious": is_suspicious,
        "flags":        flags,
        "trust_notes":  trust_notes,
        "https":        url_clean.startswith("https://"),
    }


def analyze_urls_batch(urls: List[str]) -> List[Dict]:
    """Analyze a list of URLs."""
    return [analyze_url_extended(u) for u in urls]
