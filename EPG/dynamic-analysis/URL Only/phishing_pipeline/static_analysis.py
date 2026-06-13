"""
static_analysis.py — Step 5: Lexical / static URL feature extraction.

All features are computed locally from the URL string itself —
no network requests are made here.
"""

import re
from urllib.parse import urlparse

import tldextract

from .config import SHORTENER_DOMAINS
from .logger import get_logger

log = get_logger("static_analysis")

# IPv4 in host (e.g. http://192.168.1.1/login)
_IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
)
# IPv6 in host (e.g. http://[::1]/path)
_IPV6_RE = re.compile(r"^\[.*\]$")

# One or more consecutive digit runs in the hostname
_DIGIT_BLOCK_RE = re.compile(r"\d+")

# Percent-encoded non-ASCII bytes (e.g. %E5%8D%8A = Chinese char)
# Three consecutive %XX sequences where X is A-F / 8-9 (multi-byte UTF-8)
_ENCODED_NONASCII_RE = re.compile(r"(?:%[89A-Fa-f][0-9A-Fa-f]){2,}")


def analyze_static(url: str) -> dict:
    """
    Compute lexical / static features from the raw URL string.

    Features returned:
        url_len                 — total character length of the URL
        at_sign                 — number of '@' characters
        question_mark           — number of '?' characters
        hyphen                  — number of '-' characters
        equals                  — number of '=' characters
        dots                    — number of '.' characters
        digits                  — total digit characters in the full URL
        letters                 — total letter characters in the full URL
        having_ip_address       — 1 if the host looks like an IP address
        shortening_service      — 1 if the domain is a known URL shortener
        abnormal_url            — 1 if registered domain is absent from netloc
        phish_adv_hyphen_count  — count of hyphens in the hostname only
        phish_adv_number_count  — count of digit sequences in the hostname

    Args:
        url: URL string (raw or normalized).

    Returns:
        Dict of static analysis features.
    """
    defaults = {
        "url_len": 0,
        "at_sign": 0,
        "question_mark": 0,
        "hyphen": 0,
        "equals": 0,
        "dots": 0,
        "digits": 0,
        "letters": 0,
        "having_ip_address": 0,
        "shortening_service": 0,
        "abnormal_url": 0,
        "phish_adv_hyphen_count": 0,
        "phish_adv_number_count": 0,
        "phish_encoded_non_ascii": 0,   # NEW: percent-encoded non-ASCII in path
    }

    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        # Strip port if present
        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]

        ext = tldextract.extract(url)
        registered = ext.registered_domain.lower() if ext.registered_domain else ""

        # ── Whole-URL character counts ────────────────────────────────────────
        defaults["url_len"]       = len(url)
        defaults["at_sign"]       = url.count("@")
        defaults["question_mark"] = url.count("?")
        defaults["hyphen"]        = url.count("-")
        defaults["equals"]        = url.count("=")
        defaults["dots"]          = url.count(".")
        defaults["digits"]        = sum(c.isdigit() for c in url)
        defaults["letters"]       = sum(c.isalpha() for c in url)

        # ── IP address in host ────────────────────────────────────────────────
        if _IPV4_RE.match(host) or _IPV6_RE.match(host):
            defaults["having_ip_address"] = 1

        # ── Known URL shortener ───────────────────────────────────────────────
        if registered in SHORTENER_DOMAINS or host in SHORTENER_DOMAINS:
            defaults["shortening_service"] = 1

        # ── Abnormal URL: registered domain missing from netloc ───────────────
        # A mismatch can indicate IDN homograph or embedded credentials.
        if registered and registered not in host:
            defaults["abnormal_url"] = 1

        # ── Hostname-specific hyphen & digit counts ───────────────────────────
        defaults["phish_adv_hyphen_count"] = host.count("-")
        defaults["phish_adv_number_count"] = len(_DIGIT_BLOCK_RE.findall(host))

        # ── Percent-encoded non-ASCII in URL path ────────────────────────
        # URLs like http://9779.info/%E5%8D%8A%AE... use multi-byte percent
        # encoding to embed non-Latin characters (Chinese, Arabic, Cyrillic).
        # Legitimate Western services rarely do this; it is common in
        # malware downloads, defacement pages, and content farms.
        if _ENCODED_NONASCII_RE.search(parsed.path + parsed.query):
            defaults["phish_encoded_non_ascii"] = 1

        log.debug("Static analysis for '%s': %s", url, defaults)
        return defaults

    except Exception as exc:
        log.warning("analyze_static failed for '%s': %s", url, exc)
        return defaults
