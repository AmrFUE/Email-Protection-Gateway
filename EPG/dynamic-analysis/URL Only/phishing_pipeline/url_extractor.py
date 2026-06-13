"""
url_extractor.py — Step 1: Extract all URLs from raw email text.

Handles two URL formats:
  1. Full URLs with scheme:    http://example.com/path
  2. Bare URLs without scheme: example.com/path  (auto-prepends https://)

Bare URL detection uses a heuristic: the string must start with a known
domain-like pattern (word chars, optional subdomain dots) and contain at
least one dot, followed optionally by a path / query string.
"""

import re
from .logger import get_logger

log = get_logger("url_extractor")

# ── Pattern 1: Full URLs with http / https scheme ─────────────────────────────
_FULL_URL_RE: re.Pattern = re.compile(
    r"https?://"
    r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)

# ── Pattern 2: Bare URLs — no scheme, but look like domain[/path][?query] ────
# Matches strings like:
#   amazon.com/Products/dp/B00007
#   secure.login.example.tk/verify?id=1
#   en.wikipedia.org/wiki/title
# Must have at least one dot in the host portion, starts with word character.
_BARE_URL_RE: re.Pattern = re.compile(
    r"(?<![/@\w])"              # not preceded by @, / or alphanumeric (avoid emails)
    r"(?:www\.)?"               # optional www.
    r"[A-Za-z0-9]"             # starts with alphanumeric
    r"[A-Za-z0-9\-]*"          # remainder of the first label
    r"(?:\.[A-Za-z0-9\-]+)+"   # at least one more dot-separated label (forces TLD)
    r"(?::[0-9]+)?"             # optional port
    r"(?:/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?" # optional path/query
    r"(?=[,\s\"'<>\)\]|]|$)",  # must be followed by whitespace/punctuation or EOL
    re.IGNORECASE,
)

# Known single-word TLDs to validate bare URLs (avoids matching plain words)
_VALID_TLDS: frozenset[str] = frozenset([
    "com", "net", "org", "edu", "gov", "io", "co", "uk", "de", "fr",
    "ru", "cn", "jp", "au", "ca", "it", "es", "br", "in", "nl", "pl",
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "cc", "info",
    "biz", "tv", "me", "us", "eu", "online", "site", "web", "store",
    "shop", "app", "dev", "tech", "news", "media", "live", "click",
    "link", "win", "racing", "stream", "review", "loan", "work",
    "php", "html", "htm",   # file extensions often appear at end of bare paths
])

_STRIP_TRAILING: str = ".,;:!?)>\"'"


def _has_valid_tld(url_fragment: str) -> bool:
    """
    Return True if the first component of the URL fragment (the hostname part)
    ends with a known TLD, or if the fragment contains a path (/ present after
    the first dot), which is a strong signal of a URL.
    """
    # Split off path/query
    host = url_fragment.split("/")[0].split("?")[0].split("#")[0]
    # Strip port
    if ":" in host:
        host = host.split(":")[0]
    parts = host.rsplit(".", 1)
    if len(parts) < 2:
        return False
    tld = parts[-1].lower()
    # Accept if TLD is known OR if there is a path component (strongly URL-like)
    return tld in _VALID_TLDS or "/" in url_fragment


def extract_urls(text: str) -> list[str]:
    """
    Extract all HTTP/HTTPS and bare URLs from the given text.

    Full URLs (with scheme) are returned as-is.
    Bare URLs (without scheme) have 'https://' prepended automatically.

    Args:
        text: Raw email body, CSV cell, or any string.

    Returns:
        Ordered list of URL strings (duplicates preserved).
    """
    if not text:
        log.warning("extract_urls received empty text.")
        return []

    collected: list[str] = []
    seen: set[str] = set()

    def _add(u: str) -> None:
        u = u.rstrip(_STRIP_TRAILING)
        if u and u not in seen:
            seen.add(u)
            collected.append(u)

    # ── Pass 1: Full URLs with scheme ─────────────────────────────────────────
    full_matches: list[tuple[int, int]] = []
    for m in _FULL_URL_RE.finditer(text):
        _add(m.group())
        full_matches.append((m.start(), m.end()))

    # ── Pass 2: Bare URLs (skip spans already captured in pass 1) ────────────
    for m in _BARE_URL_RE.finditer(text):
        # Skip if this span overlaps a full URL already captured
        start, end = m.start(), m.end()
        if any(fs <= start < fe or fs < end <= fe for fs, fe in full_matches):
            continue

        fragment = m.group().rstrip(_STRIP_TRAILING)
        if not fragment:
            continue

        if not _has_valid_tld(fragment):
            continue

        # Prepend scheme for bare URLs
        full_url = "https://" + fragment
        _add(full_url)

    log.info("Extracted %d URL(s) from input text.", len(collected))
    return collected
