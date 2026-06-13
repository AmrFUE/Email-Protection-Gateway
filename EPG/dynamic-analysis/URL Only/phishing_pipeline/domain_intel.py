"""
domain_intel.py — Step 4: Domain intelligence features.

Uses tldextract to cleanly split the URL into subdomain / domain / suffix,
then computes several phishing-indicative domain features.
"""

from urllib.parse import urlparse

import tldextract

from .config import SUSPICIOUS_TLDS
from .logger import get_logger

log = get_logger("domain_intel")


def analyze_domain(url: str) -> dict:
    """
    Extract domain intelligence features from a URL.

    Features returned:
        domain                  — registered domain (e.g. "example.com")
        phish_multiple_subdomains — 1 if the URL has 2+ subdomain levels
        phish_adv_long_domain   — 1 if domain length > 30 characters
        phish_suspicious_tld    — 1 if TLD is in the suspicious list
        is_gov_edu              — 1 if TLD is .gov or .edu

    Args:
        url: Normalized URL string.

    Returns:
        Dict of domain intelligence features.
    """
    defaults = {
        "domain": "",
        "phish_multiple_subdomains": 0,
        "phish_adv_long_domain": 0,
        "phish_suspicious_tld": 0,
        "is_gov_edu": 0,
    }

    try:
        ext = tldextract.extract(url)

        # Registered domain (domain + suffix)
        registered = ext.registered_domain or ""
        defaults["domain"] = registered

        # ── phish_multiple_subdomains ─────────────────────────────────────────
        # Counts how many dot-separated parts exist in the subdomain string.
        # e.g. "secure.login.evil" → 3 parts → flag = 1
        subdomain_parts = [p for p in ext.subdomain.split(".") if p]
        defaults["phish_multiple_subdomains"] = 1 if len(subdomain_parts) >= 2 else 0

        # ── phish_adv_long_domain ─────────────────────────────────────────────
        # Long domain names are a common evasion tactic; threshold is 30 chars.
        defaults["phish_adv_long_domain"] = 1 if len(registered) > 30 else 0

        # ── phish_suspicious_tld ──────────────────────────────────────────────
        suffix = ext.suffix.lower().lstrip(".")
        defaults["phish_suspicious_tld"] = 1 if suffix in SUSPICIOUS_TLDS else 0

        # ── is_gov_edu ────────────────────────────────────────────────────────
        defaults["is_gov_edu"] = 1 if suffix in ("gov", "edu") else 0

        log.debug("Domain intel for '%s': %s", url, defaults)
        return defaults

    except Exception as exc:
        log.warning("analyze_domain failed for '%s': %s", url, exc)
        return defaults
